package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUserStore_PicksUpChangesAndKeepsLastGoodOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	if err := SetUserHash(path, "alice", "hash1"); err != nil {
		t.Fatal(err)
	}
	s, err := NewUserStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if rec, ok := s.Lookup("alice"); !ok || rec.Hash != "hash1" {
		t.Fatalf("Lookup(alice) = %+v, %v", rec, ok)
	}

	// A new password and a revocation marker written by the CLI.
	if err := SetUserHash(path, "alice", "hash2"); err != nil {
		t.Fatal(err)
	}
	if err := RevokeSessions(path, "alice", false); err != nil {
		t.Fatal(err)
	}
	// Make the change visible even on a coarse-mtime filesystem.
	later := time.Now().Add(time.Hour)
	os.Chtimes(path, later, later)
	if changed, err := s.Reload(); err != nil || !changed {
		t.Fatalf("Reload() = %v, %v; want a change", changed, err)
	}
	rec, _ := s.Lookup("alice")
	if rec.Hash != "hash2" || rec.ValidAfter.IsZero() {
		t.Fatalf("after reload alice = %+v, want new hash and a ValidAfter marker", rec)
	}
	if changed, _ := s.Reload(); changed {
		t.Fatal("Reload() with no change reported a change")
	}

	// A broken edit must not lock everyone out.
	os.WriteFile(path, []byte("not a valid line\n"), 0o600)
	later = later.Add(time.Hour)
	os.Chtimes(path, later, later)
	if _, err := s.Reload(); err == nil {
		t.Fatal("Reload() of a malformed file = nil error")
	}
	if rec, ok := s.Lookup("alice"); !ok || rec.Hash != "hash2" {
		t.Fatalf("after a bad edit alice = %+v, %v; want the last good contents", rec, ok)
	}
}

func TestSessionManager_StoreRevocationApplies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	SetUserHash(path, "alice", "h")
	store, _ := NewUserStore(path)
	mgr := NewSessionManager([]byte("secret"), time.Hour)
	mgr.Store = store
	sess, _ := mgr.New("alice")
	token, _ := mgr.Encode(sess)
	if _, err := mgr.Decode(token); err != nil {
		t.Fatalf("Decode before revoke = %v", err)
	}
	time.Sleep(1100 * time.Millisecond) // ValidAfter has 1s resolution
	RevokeSessions(path, "alice", false)
	later := time.Now().Add(time.Hour)
	os.Chtimes(path, later, later)
	store.Reload()
	if _, err := mgr.Decode(token); err != ErrSessionRevoked {
		t.Fatalf("Decode after live revoke = %v, want ErrSessionRevoked", err)
	}
}
