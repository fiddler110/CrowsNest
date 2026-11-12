package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// SessionRecord is one signed-in device, kept on the server so it can be listed and ended on its own. The cookie
// still carries the signed Session; the record only says whether that session's ID is still wanted.
type SessionRecord struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Created   time.Time `json:"created"`
	LastSeen  time.Time `json:"last_seen"`
	Expires   time.Time `json:"expires"`
	UserAgent string    `json:"user_agent,omitempty"`
	IP        string    `json:"ip,omitempty"`
}

// touchEvery is how often a request moves a session's last-seen time (and so how often the store is written).
const touchEvery = time.Minute

// SessionStore is the server-side list of live sessions. A session whose ID is not in it is rejected, so
// removing a record signs that device out at once. It is saved to a small JSON file (nothing in it can be used
// to sign in: the cookie needs the HMAC too) so a restart keeps people signed in.
type SessionStore struct {
	path string

	mu        sync.Mutex
	recs      map[string]*SessionRecord
	lastFlush time.Time
	dirty     bool
}

// NewSessionStore opens path; a missing file is an empty store, and an empty path keeps the sessions in memory only.
func NewSessionStore(path string) (*SessionStore, error) {
	s := &SessionStore{path: path, recs: map[string]*SessionRecord{}}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path derives from the operator's config.yaml
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: read %s: %w", path, err)
	}
	var list []SessionRecord
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	now := time.Now()
	for i := range list {
		if list[i].ID != "" && list[i].Expires.After(now) {
			r := list[i]
			s.recs[r.ID] = &r
		}
	}
	return s, nil
}

// NewSessionID returns a random identifier for a session.
func NewSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generate session id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Add records a new session and saves.
func (s *SessionStore) Add(rec SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, r := range s.recs {
		if !r.Expires.After(now) {
			delete(s.recs, id)
		}
	}
	r := rec
	s.recs[rec.ID] = &r
	return s.flushLocked(now)
}

// Touch says whether the session is still live, and moves its last-seen time forward (saved at most once a minute).
func (s *SessionStore) Touch(id string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok || !r.Expires.After(now) {
		return false
	}
	if now.Sub(r.LastSeen) >= touchEvery {
		r.LastSeen = now
		s.dirty = true
		if now.Sub(s.lastFlush) >= touchEvery {
			_ = s.flushLocked(now) // best effort: a lost last-seen time is not worth failing a request
		}
	}
	return true
}

// List is the user's live sessions, newest first.
func (s *SessionStore) List(user string) []SessionRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var out []SessionRecord
	for _, r := range s.recs {
		if r.User == user && r.Expires.After(now) {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// Revoke ends one of user's sessions. It reports whether there was one (a session of someone else is not found).
func (s *SessionStore) Revoke(user, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok || r.User != user {
		return false, nil
	}
	delete(s.recs, id)
	return true, s.flushLocked(time.Now())
}

// RevokeAll ends every session of user except keep (pass "" to end them all) and returns how many it ended.
func (s *SessionStore) RevokeAll(user, keep string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, r := range s.recs {
		if r.User == user && id != keep {
			delete(s.recs, id)
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, s.flushLocked(time.Now())
}

func (s *SessionStore) flushLocked(now time.Time) error {
	s.lastFlush, s.dirty = now, false
	if s.path == "" {
		return nil
	}
	list := make([]SessionRecord, 0, len(s.recs))
	for _, r := range s.recs {
		list = append(list, *r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	out, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, append(out, '\n'))
}
