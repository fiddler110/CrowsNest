package auth

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadUsers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.env")
	contents := "# comment\n\nADMIN_PASSWORD_HASH=hash1\nALICE_PASSWORD_HASH=hash2\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write users file: %v", err)
	}

	users, err := LoadUsers(path)
	if err != nil {
		t.Fatalf("LoadUsers() error = %v", err)
	}
	want := Users{"admin": {Hash: "hash1"}, "alice": {Hash: "hash2"}}
	if len(users) != len(want) || !reflect.DeepEqual(users, want) {
		t.Fatalf("LoadUsers() = %+v, want %+v", users, want)
	}
}

func TestLoadUsers_ValidAfter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	contents := "ALICE_PASSWORD_HASH=hash1\nALICE_VALID_AFTER=1700000000\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write users file: %v", err)
	}

	users, err := LoadUsers(path)
	if err != nil {
		t.Fatalf("LoadUsers() error = %v", err)
	}
	rec, ok := users["alice"]
	if !ok || rec.Hash != "hash1" {
		t.Fatalf("LoadUsers() = %+v, want alice with hash1", users)
	}
	if rec.ValidAfter.Unix() != 1700000000 {
		t.Fatalf("ValidAfter = %v, want unix 1700000000", rec.ValidAfter)
	}
}

func TestLoadUsers_ValidAfterNotAnInt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	os.WriteFile(path, []byte("ALICE_PASSWORD_HASH=hash1\nALICE_VALID_AFTER=nope\n"), 0o600)

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
	if err := SetUserHash(path, "alice", "hash2"); err != nil {
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
	if users["admin"].Hash != "hash1-updated" || users["alice"].Hash != "hash2" {
		t.Fatalf("LoadUsers() = %+v, want admin updated and alice preserved", users)
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
	if err := SetUserHash(path, "alice", "hash1"); err != nil {
		t.Fatalf("SetUserHash() error = %v", err)
	}

	before := time.Now().Add(-time.Second)
	if err := RevokeSessions(path, "Alice", false); err != nil {
		t.Fatalf("RevokeSessions() error = %v", err)
	}

	users, err := LoadUsers(path)
	if err != nil {
		t.Fatalf("LoadUsers() error = %v", err)
	}
	rec, ok := users["alice"]
	if !ok || rec.Hash != "hash1" {
		t.Fatalf("LoadUsers() = %+v, want alice's hash preserved", users)
	}
	if rec.ValidAfter.Before(before) {
		t.Fatalf("ValidAfter = %v, want a timestamp at/after %v", rec.ValidAfter, before)
	}
}

func TestRevokeSessions_UnknownUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	if err := RevokeSessions(path, "ghost", false); err == nil {
		t.Fatal("RevokeSessions() error = nil, want error for a user with no password set")
	}
}

func TestRoles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	SetUserHash(path, "alice", "h")
	SetUserHash(path, "bob", "h")
	if err := SetRole(path, "bob", RolePlayer, false); err != nil {
		t.Fatal(err)
	}
	users, err := LoadUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	if users["alice"].EffectiveRole() != RoleAdmin {
		t.Fatal("a user with no role must default to admin")
	}
	if users["bob"].EffectiveRole() != RolePlayer {
		t.Fatalf("bob = %q, want player", users["bob"].EffectiveRole())
	}
	// Survives a password change and a revocation (both rewrite the file).
	SetUserHash(path, "bob", "h2")
	RevokeSessions(path, "bob", false)
	users, _ = LoadUsers(path)
	if users["bob"].Role != RolePlayer {
		t.Fatal("role lost when the users file was rewritten")
	}
	os.WriteFile(path, []byte("BOB_ROLE=superuser\n"), 0o600)
	if _, err := LoadUsers(path); err == nil {
		t.Fatal("LoadUsers accepted an invalid role")
	}
}

func TestCreateAndDeleteUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users")
	if err := CreateUser(path, "Alice", "h1", "", RolePlayer); err != nil {
		t.Fatal(err)
	}
	if err := CreateUser(path, "alice", "h2", "", RolePlayer); err == nil {
		t.Error("duplicate create succeeded")
	}
	if err := CreateUser(path, "a=b", "h", "", RolePlayer); err == nil {
		t.Error("invalid username accepted")
	}
	users, _ := LoadUsers(path)
	if users["alice"].Hash != "h1" || users["alice"].Role != RolePlayer {
		t.Errorf("alice = %+v", users["alice"])
	}
	if err := DeleteUser(path, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser(path, "alice"); err == nil {
		t.Error("deleting a missing user succeeded")
	}
}

func TestCreateFirstAdmin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	if err := CreateFirstAdmin(path, "Boss", "hash", ""); err != nil {
		t.Fatal(err)
	}
	users, _ := LoadUsers(path)
	if r := users["boss"]; r.Role != RoleAdmin || r.Hash != "hash" {
		t.Fatalf("first admin = %+v", r)
	}
	if err := CreateFirstAdmin(path, "other", "hash", ""); !errors.Is(err, ErrSetupDone) {
		t.Fatalf("second first-admin = %v, want ErrSetupDone", err)
	}
	if err := CreateFirstAdmin(filepath.Join(t.TempDir(), "u.env"), "x", "", ""); err == nil {
		t.Fatal("a user with neither password nor Google email must be refused")
	}
}

func TestClearPasswordHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.env")
	// alex is an older account: a hash and no explicit role (so an implicit admin).
	if err := SetUserHash(path, "alex", "hash1"); err != nil {
		t.Fatal(err)
	}
	if err := SetGoogleEmail(path, "alex", "alex@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := CreateUser(path, "sam", "hash2", "", RolePlayer); err != nil {
		t.Fatal(err)
	}

	// No other way in: refused, and nothing changes.
	if err := ClearPasswordHash(path, "sam", false); err == nil {
		t.Fatal("cleared the only way for sam to sign in")
	}
	if err := ClearPasswordHash(path, "sam", true); err != nil {
		t.Fatalf("with another login allowed: %v", err)
	}

	// alex has a Google email on file. The implicit admin role is made explicit.
	if err := ClearPasswordHash(path, "alex", false); err != nil {
		t.Fatal(err)
	}
	users, _ := LoadUsers(path)
	a := users["alex"]
	if a.Hash != "" || a.Role != RoleAdmin || a.GoogleEmail != "alex@example.com" {
		t.Fatalf("alex after clear: %+v", a)
	}
	if a.EffectiveRole() != RoleAdmin {
		t.Error("clearing the hash demoted an admin")
	}
	if err := ClearPasswordHash(path, "alex", true); err == nil {
		t.Error("clearing twice should say there is no password")
	}
	if err := ClearPasswordHash(path, "nobody", true); err == nil {
		t.Error("unknown user accepted")
	}
}

func TestImportGoogleEmails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users")
	emails := GoogleUsers{"a@x.org": "alice", "b@x.org": "bob", "a2@x.org": "alice"}
	if imp, _, err := ImportGoogleEmails(path, emails); err != nil || len(imp) != 0 {
		t.Fatalf("empty file: imported %v, err %v; want nothing so first-run setup stays open", imp, err)
	}
	if err := CreateUser(path, "alice", "$2a$x", "", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	imp, skipped, err := ImportGoogleEmails(path, emails)
	if err != nil || len(imp) != 2 || len(skipped) != 1 || skipped[0] != "a@x.org" && skipped[0] != "a2@x.org" {
		t.Fatalf("imported %v skipped %v err %v", imp, skipped, err)
	}
	users, _ := LoadUsers(path)
	if users["alice"].GoogleEmail == "" || users["alice"].Role != RoleAdmin || users["bob"].GoogleEmail != "b@x.org" || users["bob"].Role != RolePlayer {
		t.Fatalf("users = %+v", users)
	}
}
