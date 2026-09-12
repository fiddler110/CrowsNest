package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	want := Users{"admin": "hash1", "scott": "hash2"}
	if len(users) != len(want) || users["admin"] != "hash1" || users["scott"] != "hash2" {
		t.Fatalf("LoadUsers() = %+v, want %+v", users, want)
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
	if users["admin"] != "hash1-updated" || users["scott"] != "hash2" {
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
