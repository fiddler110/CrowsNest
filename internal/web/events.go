package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/sse"
)

const (
	// defaultMaxEventStreams bounds open /api/events connections (one per
	// dashboard tab). They are cheap, a goroutine reading the hub, but not
	// free.
	defaultMaxEventStreams = 32
	// defaultMaxEventStreamsPerUser keeps one user's tabs from using up the
	// shared cap and pushing everyone else onto polling.
	defaultMaxEventStreamsPerUser = 4
	// defaultEventsMinGap spaces sends: a burst of hub changes (a start
	// flipping several states in a row) costs one send.
	defaultEventsMinGap = time.Second
	// eventsKeepalive is the heartbeat comment interval.
	eventsKeepalive = 25 * time.Second
	// eventsRefresh re-reads state that changes without a hub notification
	// (the idle countdown appearing, docker health) and sends what differs.
	eventsRefresh = 30 * time.Second
)

// acquireSlot reserves one of max slots counted by n.
func acquireSlot(n *atomic.Int32, max int) bool {
	for {
		cur := n.Load()
		if int(cur) >= max {
			return false
		}
		if n.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// userStreams counts open event streams per username.
type userStreams struct {
	mu sync.Mutex
	n  map[string]int
}

// acquire reserves one of max slots for user.
func (u *userStreams) acquire(user string, max int) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.n[user] >= max {
		return false
	}
	if u.n == nil {
		u.n = map[string]int{}
	}
	u.n[user]++
	return true
}

func (u *userStreams) release(user string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.n[user]--; u.n[user] <= 0 {
		delete(u.n, user)
	}
}

// handleEvents streams the dashboard's live state as Server-Sent Events:
//
//	event: games   data: the /api/games body for this user
//	event: health  data: the /api/health body
//
// Both are sent on connect, then whenever they change: games on every state
// hub notification (observations, exclusivity's starting/stopping and start
// results), at most once per EventsMinGap; health is re-checked with them
// and every eventsRefresh. A comment line every eventsKeepalive keeps
// proxies from closing a quiet stream. The client falls back to polling
// /api/games and /api/health when the stream fails.
func (a *App) handleEvents(w http.ResponseWriter, r *http.Request) {
	if a.Hub == nil {
		http.Error(w, "live updates unavailable", http.StatusServiceUnavailable)
		return
	}
	max := a.MaxEventStreams
	if max <= 0 {
		max = defaultMaxEventStreams
	}
	perUser := a.MaxEventStreamsPerUser
	if perUser <= 0 {
		perUser = defaultMaxEventStreamsPerUser
	}
	sess, err := auth.DecodeSessionCookie(a.Auth.Sessions, r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// The per-user slot is taken first so a user at their limit never holds
	// a global one.
	if !a.userEventStreams.acquire(sess.Username, perUser) {
		http.Error(w, "too many live update streams for this user", http.StatusTooManyRequests)
		return
	}
	defer a.userEventStreams.release(sess.Username)
	if !acquireSlot(&a.eventStreams, max) {
		http.Error(w, "too many live update streams, try again shortly", http.StatusServiceUnavailable)
		return
	}
	defer a.eventStreams.Add(-1)

	sub := a.Hub.Subscribe()
	defer sub.Close()
	sw, ok := sse.NewWriter(w)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	gap := a.EventsMinGap
	if gap <= 0 {
		gap = defaultEventsMinGap
	}
	keepalive := eventsKeepalive
	if a.KeepaliveInterval > 0 {
		keepalive = a.KeepaliveInterval
	}

	var lastGames, lastHealth []byte
	var lastSent time.Time
	// send writes event with v's JSON unless it is what was last sent.
	send := func(event string, v any, last *[]byte) error {
		b, err := json.Marshal(v)
		if err != nil || bytes.Equal(b, *last) {
			return err
		}
		*last = b
		return sw.WriteEvent(event, string(b))
	}
	update := func() error {
		// The session was checked at connect; re-check it so an expired or
		// revoked one ends the stream (the client's fallback poll then
		// meets the 401 and goes to the login page).
		if _, err := auth.DecodeSessionCookie(a.Auth.Sessions, r); err != nil {
			return err
		}
		lastSent = time.Now()
		if err := send("games", a.listGames(r), &lastGames); err != nil {
			return err
		}
		return send("health", a.health(r.Context()), &lastHealth)
	}
	if update() != nil {
		return
	}

	beat := time.NewTicker(keepalive)
	defer beat.Stop()
	refresh := time.NewTicker(eventsRefresh)
	defer refresh.Stop()
	var due <-chan time.Time // set while a coalesced send is waiting
	for {
		var err error
		select {
		case <-r.Context().Done():
			return
		case <-sub.C:
			if due != nil {
				continue
			}
			if wait := gap - time.Since(lastSent); wait > 0 {
				due = time.After(wait)
				continue
			}
			err = update()
		case <-due:
			due = nil
			err = update()
		case <-refresh.C:
			err = update()
		case <-beat.C:
			err = sw.WriteComment("keepalive")
		}
		if err != nil {
			return
		}
	}
}
