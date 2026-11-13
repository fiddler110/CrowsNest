package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/audit"
	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/games"
)

func TestRunState_ExportAndRestoreCLI(t *testing.T) {
	cfgPath := writeTestConfig(t, ":5000")
	t.Setenv("CROWSNEST_CONFIG", cfgPath)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.UsersFile, []byte("A_HASH=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "snap.tar.gz")
	var out bytes.Buffer
	if err := runState([]string{"export", "-o", dest}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "users/") || !strings.Contains(out.String(), "Not included") {
		t.Errorf("export output: %s", out.String())
	}
	// A second export to the same file must not overwrite it.
	if err := runState([]string{"export", "-o", dest}, &out); err == nil {
		t.Error("export over an existing file must fail")
	}
	// Restore: refused over existing files, fine with --force.
	if err := runState([]string{"restore", dest}, &out); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("restore without --force = %v", err)
	}
	if err := runState([]string{"restore", dest, "--force"}, &out); err != nil {
		t.Errorf("restore --force = %v", err)
	}
	if err := runState([]string{"restore", filepath.Join(t.TempDir(), "missing.tar.gz")}, &out); err == nil {
		t.Error("restore of a missing file must fail")
	}
	for _, bad := range [][]string{nil, {"bogus"}, {"export", "extra"}, {"restore"}, {"restore", "a", "b"}, {"restore", "-x"}} {
		if err := runState(bad, &out); err == nil || !strings.Contains(err.Error(), "usage") && len(bad) > 0 && bad[0] != "restore" {
			t.Errorf("runState(%v) = %v", bad, err)
		}
	}
}

func TestStateRestoreRejectsNonArchiveAndEmpty(t *testing.T) {
	cfg, _ := stateConfig(t)
	if err := stateRestore(cfg, strings.NewReader("not gzip"), true, &bytes.Buffer{}); err == nil {
		t.Error("garbage must be refused")
	}
}

func TestClearPasswordAndEnablePasswordLogin(t *testing.T) {
	cfgPath := writeTestConfig(t, ":5000")
	b, _ := os.ReadFile(cfgPath)
	settings := filepath.Join(filepath.Dir(cfgPath), "settings.json")
	b = bytes.Replace(b, []byte("server:\n"), []byte("server:\n  settings_file: "+settings+"\n"), 1)
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CROWSNEST_CONFIG", cfgPath)
	withStdin(t, "pw-one\n")
	if err := setPassword("bob"); err != nil {
		t.Fatal(err)
	}
	// No Google sign-in is set up, so the only login method must stay.
	if err := clearPassword("bob"); err == nil {
		t.Error("clearing the only way in must be refused")
	}
	if err := enablePasswordLogin(); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(cfgPath)
	if _, err := os.Stat(filepath.Join(filepath.Dir(cfg.Server.SettingsFile), "auth-prefs.json")); err != nil {
		t.Errorf("preference not saved: %v", err)
	}
}

func TestImportLegacyGoogleUsers(t *testing.T) {
	cfgPath := writeTestConfig(t, ":5000")
	cfg, _ := config.Load(cfgPath)
	cfg.Auth.Google = &config.GoogleAuthConfig{UsersEnv: "CN_TEST_GOOGLE_USERS"}
	cfg.Server.SettingsFile = filepath.Join(t.TempDir(), "settings.json")
	store, err := auth.NewUserStore(cfg.UsersFile)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(filepath.Dir(cfg.Server.SettingsFile), "google-users-imported")

	// Unset variable: nothing happens.
	importLegacyGoogleUsers(cfg, store)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("marker written with nothing to import")
	}
	t.Setenv("CN_TEST_GOOGLE_USERS", "carol=carol@example.com")
	// Empty users file: waits for the first admin.
	importLegacyGoogleUsers(cfg, store)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("imported before the first admin exists")
	}
	withStdin(t, "pw\n")
	t.Setenv("CROWSNEST_CONFIG", cfgPath)
	if err := setPassword("carol"); err != nil {
		t.Fatal(err)
	}
	importLegacyGoogleUsers(cfg, store)
	users, _ := auth.LoadUsers(cfg.UsersFile)
	if users["carol"].GoogleEmail != "carol@example.com" {
		t.Errorf("email not imported: %+v", users["carol"])
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("marker missing: %v", err)
	}
	// Second run is a no-op even if the variable changes.
	t.Setenv("CN_TEST_GOOGLE_USERS", "carol=other@example.com")
	importLegacyGoogleUsers(cfg, store)
	users, _ = auth.LoadUsers(cfg.UsersFile)
	if users["carol"].GoogleEmail != "carol@example.com" {
		t.Error("import ran twice")
	}
	// No Google config at all.
	cfg.Auth.Google = nil
	importLegacyGoogleUsers(cfg, store)
}

func TestWriteOutFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "o.txt")
	if err := writeOut(p, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "hi" {
		t.Errorf("got %q", b)
	}
	if err := writeOut(filepath.Join(p, "x", "y"), nil); err == nil {
		t.Error("an unwritable path must error")
	}
}

func TestRunRenderRejectsBadConfig(t *testing.T) {
	if err := runRender([]string{"--config", filepath.Join(t.TempDir(), "none.yaml")}); err == nil {
		t.Error("missing config must error")
	}
	// A game whose module has no runtime image renders nothing.
	if err := runRender([]string{"--config", writeTestConfig(t, ":5000"), "--compose", filepath.Join(t.TempDir(), "c.yaml")}); err == nil {
		t.Error("no renderable game must error")
	}
}

func TestNewMemoryBudget(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.SettingsFile = filepath.Join(t.TempDir(), "settings.json")
	reg, _ := games.NewRegistry(nil)
	cfg.Server.MemoryReserveMB = -1
	if newMemoryBudget(cfg, reg) != nil {
		t.Error("a negative reserve turns admission off")
	}
	cfg.Server.MemoryReserveMB = 0
	b := newMemoryBudget(cfg, reg)
	if b == nil || b.Reserve != 1024<<20 || b.Declared("nope") != 0 || b.Available == nil {
		t.Fatalf("budget = %+v", b)
	}
}

func TestRunAudit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	l.Record("one")
	l.Record("two")
	l.Close()
	var out bytes.Buffer
	if err := runAudit([]string{"verify", p}, &out); err != nil || !strings.Contains(out.String(), "OK, 2 entries") {
		t.Fatalf("verify: %v %q", err, out.String())
	}
	out.Reset()
	if err := runAudit([]string{"export", p}, &out); err != nil || strings.Count(out.String(), "\n") != 2 {
		t.Fatalf("export: %v %q", err, out.String())
	}
	raw, _ := os.ReadFile(p)
	os.WriteFile(p, bytes.Replace(raw, []byte("one"), []byte("uno"), 1), 0o600)
	if err := runAudit([]string{"verify", p}, &out); err == nil || !strings.Contains(err.Error(), "BROKEN") {
		t.Fatalf("a changed entry: %v", err)
	}
	if runAudit(nil, &out) == nil || runAudit([]string{"nope"}, &out) == nil {
		t.Error("bad usage accepted")
	}
}
