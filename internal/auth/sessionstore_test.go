package auth

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSessionStore_PersistsAndRevokes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	s, err := NewSessionStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	add := func(id, user string, exp time.Duration) {
		if err := s.Add(SessionRecord{ID: id, User: user, Created: now, LastSeen: now, Expires: now.Add(exp)}); err != nil {
			t.Fatal(err)
		}
	}
	add("a", "scott", time.Hour)
	add("b", "scott", time.Hour)
	add("c", "friend", time.Hour)
	add("old", "scott", -time.Minute)

	s2, err := NewSessionStore(path) // a restart keeps the live ones and drops the expired
	if err != nil {
		t.Fatal(err)
	}
	if got := len(s2.List("scott")); got != 2 {
		t.Fatalf("scott has %d sessions after reload", got)
	}
	if s2.Touch("old", now) {
		t.Error("an expired session is live")
	}
	if ok, _ := s2.Revoke("friend", "a"); ok {
		t.Error("revoked someone else's session")
	}
	if n, _ := s2.RevokeAll("scott", "a"); n != 1 || !s2.Touch("a", now) || s2.Touch("b", now) {
		t.Errorf("RevokeAll kept the wrong sessions (n=%d)", n)
	}
	s3, _ := NewSessionStore(path)
	if s3.Touch("b", now) || !s3.Touch("c", now) {
		t.Error("revocation was not saved")
	}
}

func TestSessionManager_RegistryRejectsUnknownAndLegacy(t *testing.T) {
	m := NewSessionManager([]byte("k"), time.Hour)
	reg, _ := NewSessionStore("")
	m.Registry = reg
	s, _ := m.New("scott")
	tok, _ := m.Encode(s)
	if _, err := m.Decode(tok); err != ErrSessionRevoked {
		t.Fatalf("unlisted session: %v", err)
	}
	_ = reg.Add(SessionRecord{ID: s.ID, User: "scott", Created: s.IssuedAt, LastSeen: s.IssuedAt, Expires: s.ExpiresAt})
	if _, err := m.Decode(tok); err != nil {
		t.Fatalf("listed session: %v", err)
	}
	legacy := s
	legacy.ID = ""
	tok, _ = m.Encode(legacy)
	if _, err := m.Decode(tok); err != ErrSessionRevoked {
		t.Fatalf("a cookie with no id: %v", err)
	}
	m.Registry = nil // the manager still works without a registry
	if _, err := m.Decode(tok); err != nil {
		t.Fatalf("no registry: %v", err)
	}
}
