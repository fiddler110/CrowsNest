package auth

import (
	"context"
	"log"
	"os"
	"sync"
	"time"
)

// UserStore serves the users file and picks up changes to it while running,
// so `crowsnest set-password` and `crowsnest revoke-sessions` apply at once
// instead of waiting for a restart. A file that fails to parse is logged and
// ignored: the last good contents stay in force rather than locking everyone
// out because of a half-written or mistyped line.
type UserStore struct {
	path string

	mu    sync.RWMutex
	users Users
	mtime time.Time
	size  int64
	known bool // whether the file existed at the last load
}

// NewUserStore loads path (a missing file is an empty store, like LoadUsers).
func NewUserStore(path string) (*UserStore, error) {
	s := &UserStore{path: path}
	users, err := LoadUsers(path)
	if err != nil {
		return nil, err
	}
	s.users = users
	s.mtime, s.size, s.known = s.stat()
	return s, nil
}

func (s *UserStore) stat() (time.Time, int64, bool) {
	fi, err := os.Stat(s.path)
	if err != nil {
		return time.Time{}, 0, false
	}
	return fi.ModTime(), fi.Size(), true
}

// Path is the users file this store serves.
func (s *UserStore) Path() string { return s.path }

// Lookup returns username's record.
func (s *UserStore) Lookup(username string) (UserRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.users[username]
	return rec, ok
}

// Snapshot returns the current users. The map must not be modified.
func (s *UserStore) Snapshot() Users {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users
}

// Reload re-reads the file if it changed since the last load, reporting
// whether new contents were applied.
func (s *UserStore) Reload() (bool, error) {
	mtime, size, exists := s.stat()
	s.mu.RLock()
	unchanged := mtime.Equal(s.mtime) && size == s.size && exists == s.known
	s.mu.RUnlock()
	if unchanged {
		return false, nil
	}
	users, err := LoadUsers(s.path)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	s.users, s.mtime, s.size, s.known = users, mtime, size, exists
	s.mu.Unlock()
	return true, nil
}

// Watch polls the file every interval until ctx is cancelled.
func (s *UserStore) Watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			changed, err := s.Reload()
			switch {
			case err != nil:
				log.Printf("auth: users file %s changed but could not be read; keeping the previous contents: %v", s.path, err)
			case changed:
				log.Printf("auth: users file %s reloaded", s.path)
			}
		}
	}
}

// GoogleUsers returns the Google email -> username pairs recorded in the
// users file.
func (s *UserStore) GoogleUsers() GoogleUsers {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := GoogleUsers{}
	for name, rec := range s.users {
		if rec.GoogleEmail != "" {
			out[rec.GoogleEmail] = name
		}
	}
	return out
}

// OIDCUsers returns the OIDC email -> username pairs recorded in the users
// file.
func (s *UserStore) OIDCUsers() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]string{}
	for name, rec := range s.users {
		if rec.OIDCEmail != "" {
			out[rec.OIDCEmail] = name
		}
	}
	return out
}
