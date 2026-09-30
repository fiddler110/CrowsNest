package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadUsers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.env")
	contents := "# comment\n\nADMIN_PASSWORD_HASH=hash1\nSCOTT_PASSWORD_HASH=hash2\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write users file: %v", err)
	}

	users, err := LoadUsers(path)
	if err != nil {
		t.Fatalf("LoadUsers() error = %v", err)
	}
	want := Users{"admin": {Hash: "hash1"}, "scott": {Hash: "hash2"}}
	if len(users) != len(want) || users["admin"] != want["admin"] || users["scott"] != want["scott"] {
		t.Fatalf("LoadUsers() = %+v, want %+v", users, want)
	}
}

func TestLoadUsers_ValidAfter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	contents := "SCOTT_PASSWORD_HASH=hash1\nSCOTT_VALID_AFTER=1700000000\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write users file: %v", err)
	}

	users, err := LoadUsers(path)
	if err != nil {
		t.Fatalf("LoadUsers() error = %v", err)
	}
	rec, ok := users["scott"]
	if !ok || rec.Hash != "hash1" {
		t.Fatalf("LoadUsers() = %+v, want scott with hash1", users)
	}
	if rec.ValidAfter.Unix() != 1700000000 {
		t.Fatalf("ValidAfter = %v, want unix 1700000000", rec.ValidAfter)
	}
}

func TestLoadUsers_ValidAfterNotAnInt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	os.WriteFile(path, []byte("SCOTT_PASSWORD_HASH=hash1\nSCOTT_VALID_AFTER=nope\n"), 0o600)

	_, err := LoadUsers(path)
	if err == nil {
		t.Fatal("LoadUsers() error = nil, want error for a non-integer VALID_AFTER")
	}
}

func TestLoadUsers_MissingFileReturnsEmpty(t *testing.T) {
	users, err := LoadUsers(filepath.Join(t.TempDir(), "missing.env"))
	if err != nil {
		t.Fatalf("LoadUsers() error = %v, want nil for a missing file", err)
	}
	if len(users) != 0 {
		t.Fatalf("LoadUsers() = %+v, want empty", users)
	}
}

func TestLoadUsers_BadLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	os.WriteFile(path, []byte("not a valid line\n"), 0o600)

	_, err := LoadUsers(path)
	if err == nil {
		t.Fatal("LoadUsers() error = nil, want error for a malformed line")
	}
}

func TestLoadUsers_KeyMissingSuffix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	os.WriteFile(path, []byte("ADMIN_PASSWORD=hash1\n"), 0o600)

	_, err := LoadUsers(path)
	if err == nil || !strings.Contains(err.Error(), "_PASSWORD_HASH") {
		t.Fatalf("LoadUsers() error = %v, want a suffix error", err)
	}
}

func TestSetUserHash_CreatesFileAndUpserts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")

	if err := SetUserHash(path, "Admin", "hash1"); err != nil {
		t.Fatalf("SetUserHash() error = %v", err)
	}
	if err := SetUserHash(path, "scott", "hash2"); err != nil {
		t.Fatalf("SetUserHash() error = %v", err)
	}
	// Update an existing user; the other entry must survive.
	if err := SetUserHash(path, "admin", "hash1-updated"); err != nil {
		t.Fatalf("SetUserHash() error = %v", err)
	}

	users, err := LoadUsers(path)
	if err != nil {
		t.Fatalf("LoadUsers() error = %v", err)
	}
	if users["admin"].Hash != "hash1-updated" || users["scott"].Hash != "hash2" {
		t.Fatalf("LoadUsers() = %+v, want admin updated and scott preserved", users)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat users file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("users file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestRevokeSessions_SetsValidAfterAndPreservesHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	if err := SetUserHash(path, "scott", "hash1"); err != nil {
		t.Fatalf("SetUserHash() error = %v", err)
	}

	before := time.Now().Add(-time.Second)
	if err := RevokeSessions(path, "Scott"); err != nil {
		t.Fatalf("RevokeSessions() error = %v", err)
	}

	users, err := LoadUsers(path)
	if err != nil {
		t.Fatalf("LoadUsers() error = %v", err)
	}
	rec, ok := users["scott"]
	if !ok || rec.Hash != "hash1" {
		t.Fatalf("LoadUsers() = %+v, want scott's hash preserved", users)
	}
	if rec.ValidAfter.Before(before) {
		t.Fatalf("ValidAfter = %v, want a timestamp at/after %v", rec.ValidAfter, before)
	}
}

func TestRevokeSessions_UnknownUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	if err := RevokeSessions(path, "ghost"); err == nil {
		t.Fatal("RevokeSessions() error = nil, want error for a user with no password set")
	}
}
