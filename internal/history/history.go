// Package history keeps CrowsNest's activity log: who started, stopped or
// switched a game, automatic stops, failures, setting changes, and players
// joining and leaving. Events are appended to a JSON-lines file (one event
// per line, easy to read or grep), held in memory for the dashboard, and
// pruned after a retention period. Playtime per player is derived from the
// join/leave events.
package history

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Event kinds.
const (
	KindStart       = "start"
	KindStop        = "stop"
	KindAutoStop    = "auto_stop"
	KindStartFailed = "start_failed"
	KindStopFailed  = "stop_failed"
	KindJoin        = "join"
	KindLeave       = "leave"
	KindSettings    = "settings"
	KindUsers       = "users"
	KindGames       = "games"
	KindBackup      = "backup"
	KindConsole     = "console"
	KindCrash       = "crash"
	KindCrashLoop   = "crash_loop"
)

// Event is one line of the log.
type Event struct {
	Time   time.Time `json:"t"`
	Kind   string    `json:"kind"`
	Game   string    `json:"game,omitempty"`
	Actor  string    `json:"actor,omitempty"` // the user, or the player for join/leave
	Detail string    `json:"detail,omitempty"`
}

// Recorder is what the rest of the program records events through. A nil
// *Store is a valid Recorder that discards everything.
type Recorder interface {
	Record(kind, game, actor, detail string)
}

// Store is the on-disk log plus its in-memory copy. Build with Open.
type Store struct {
	path      string
	retention time.Duration

	mu     sync.Mutex
	events []Event // chronological

	// Playtime cache: closed totals plus the start of each open visit,
	// rebuilt on demand after Record/Prune change events.
	ptValid bool
	ptTotal map[ptKey]time.Duration
	ptOpen  map[ptKey]time.Time

	// Now overrides time.Now (tests).
	Now func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Open loads path (a missing file is an empty log) and prunes anything older
// than retention. Unreadable lines are skipped, not fatal: a log shouldn't
// stop the server from starting.
func Open(path string, retention time.Duration) (*Store, error) {
	s := &Store{path: path, retention: retention}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("history: %w", err)
	}
	f, err := os.Open(path) // #nosec G304 -- operator-configured path
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return nil, fmt.Errorf("history: read %s: %w", path, err)
	default:
		defer f.Close()
		skipped := 0
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			var e Event
			if json.Unmarshal(sc.Bytes(), &e) != nil || e.Time.IsZero() {
				skipped++
				continue
			}
			s.events = append(s.events, e)
		}
		if skipped > 0 {
			log.Printf("history: skipped %d unreadable line(s) in %s", skipped, path)
		}
	}
	sort.SliceStable(s.events, func(i, j int) bool { return s.events[i].Time.Before(s.events[j].Time) })
	if err := s.Prune(); err != nil {
		return nil, err
	}
	return s, nil
}

// Record appends an event. Failures to write are logged, never returned: the
// action being recorded has already happened.
func (s *Store) Record(kind, game, actor, detail string) {
	if s == nil {
		return
	}
	e := Event{Time: s.now().UTC().Truncate(time.Second), Kind: kind, Game: game, Actor: actor, Detail: detail}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	s.ptValid = false
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- operator-configured path
	if err != nil {
		log.Printf("history: write %s: %v", s.path, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		log.Printf("history: write %s: %v", s.path, err)
	}
}

// Recent returns up to limit events, newest first, optionally only for game.
func (s *Store) Recent(limit int, game string) []Event {
	return s.RecentExcluding(limit, game)
}

// RecentExcluding is Recent skipping events of the given kinds; the filter
// runs inside the scan so the result still holds up to limit events.
func (s *Store) RecentExcluding(limit int, game string, kinds ...string) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Event{}
	for i := len(s.events) - 1; i >= 0 && len(out) < limit; i-- {
		e := s.events[i]
		if (game == "" || e.Game == game) && !slices.Contains(kinds, e.Kind) {
			out = append(out, e)
		}
	}
	return out
}

// Filter selects events for Query. Zero fields match everything.
type Filter struct {
	Game  string
	Kinds []string // any of these kinds; empty means all
	Actor string   // exact match
	Text  string   // case-insensitive substring of the actor, game or detail
	Since time.Time
	Until time.Time // exclusive
}

func (f Filter) match(e Event) bool {
	if f.Game != "" && e.Game != f.Game {
		return false
	}
	if len(f.Kinds) > 0 && !slices.Contains(f.Kinds, e.Kind) {
		return false
	}
	if f.Actor != "" && e.Actor != f.Actor {
		return false
	}
	if !f.Since.IsZero() && e.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !e.Time.Before(f.Until) {
		return false
	}
	if f.Text != "" {
		t := strings.ToLower(f.Text)
		if !strings.Contains(strings.ToLower(e.Actor+"\n"+e.Game+"\n"+e.Detail), t) {
			return false
		}
	}
	return true
}

// Query returns up to limit events matching f, newest first, skipping the
// first offset matches. more reports whether further matches exist.
func (s *Store) Query(f Filter, offset, limit int) (events []Event, more bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	events = []Event{}
	skipped := 0
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if !f.match(e) {
			continue
		}
		if skipped < offset {
			skipped++
			continue
		}
		if len(events) == limit {
			return events, true
		}
		events = append(events, e)
	}
	return events, false
}

// Prune drops events older than the retention period, rewriting the file
// atomically when anything was removed.
func (s *Store) Prune() error {
	if s.retention <= 0 {
		return nil
	}
	cutoff := s.now().Add(-s.retention)
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := 0
	for keep < len(s.events) && s.events[keep].Time.Before(cutoff) {
		keep++
	}
	if keep == 0 {
		return nil
	}
	s.events = append([]Event(nil), s.events[keep:]...)
	s.ptValid = false

	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".history-*")
	if err != nil {
		return fmt.Errorf("history: prune: %w", err)
	}
	defer os.Remove(tmp.Name())
	w := bufio.NewWriter(tmp)
	for _, e := range s.events {
		b, _ := json.Marshal(e)
		_, _ = w.Write(append(b, '\n'))
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("history: prune: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("history: prune: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("history: prune: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("history: prune: %w", err)
	}
	return nil
}

// RunPruner prunes once a day until ctx is cancelled.
func (s *Store) RunPruner(ctx context.Context) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Prune(); err != nil {
				log.Printf("history: %v", err)
			}
		}
	}
}

// Playtime is the total time a player has spent in a game.
type Playtime struct {
	Player  string `json:"player"`
	Game    string `json:"game"`
	Seconds int64  `json:"seconds"`
}

// Playtime totals time per (player, game) from join/leave events, longest
// first. A visit ends at the player's leave, or when the game is stopped; a
// visit with no end yet runs to now. A leave with no recorded join (the
// player was already aboard when CrowsNest began watching) is ignored.
func (s *Store) Playtime() []Playtime {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.ptValid {
		s.rebuildPlaytime()
	}
	total := maps.Clone(s.ptTotal)
	for k, st := range s.ptOpen {
		total[k] += now.Sub(st)
	}
	out := make([]Playtime, 0, len(total))
	for k, d := range total {
		if d > 0 {
			out = append(out, Playtime{Player: k.player, Game: k.game, Seconds: int64(d.Seconds())})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seconds != out[j].Seconds {
			return out[i].Seconds > out[j].Seconds
		}
		return out[i].Player+out[i].Game < out[j].Player+out[j].Game
	})
	return out
}

type ptKey struct{ game, player string }

// rebuildPlaytime recomputes the closed totals and open visits from all
// events. Caller holds s.mu.
func (s *Store) rebuildPlaytime() {
	open := map[ptKey]time.Time{}
	total := map[ptKey]time.Duration{}
	for _, e := range s.events {
		switch e.Kind {
		case KindJoin:
			if _, ok := open[ptKey{e.Game, e.Actor}]; !ok {
				open[ptKey{e.Game, e.Actor}] = e.Time
			}
		case KindLeave:
			k := ptKey{e.Game, e.Actor}
			if st, ok := open[k]; ok {
				total[k] += e.Time.Sub(st)
				delete(open, k)
			}
		case KindStop, KindAutoStop:
			for k, st := range open {
				if k.game == e.Game {
					total[k] += e.Time.Sub(st)
					delete(open, k)
				}
			}
		}
	}
	s.ptTotal, s.ptOpen, s.ptValid = total, open, true
}
