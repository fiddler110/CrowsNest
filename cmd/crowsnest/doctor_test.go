package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/config"
)

type fakePing struct{ err error }

func (f fakePing) Ping(context.Context) error { return f.err }

// doctorConfig is a config whose files all live under a fresh directory.
func doctorConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	y := "server:\n  session_secret_file: " + dir + "/secret\n  settings_file: " + dir + "/settings.json\n  history_file: " + dir + "/events.jsonl\n  docker_host: tcp://guard:2375\n  secure_cookies: true\nusers_file: " + dir + "/users.env\ngames:\n  - id: windrose\n    display_name: Windrose\n    container_name: windrose\n    compose_file: /data/compose.yaml\n    compose_profile: windrose\n    compose_service: windrose\n"
	if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestDoctor_HealthyInstallHasNoFailures(t *testing.T) {
	var out strings.Builder
	if code := runDoctor(doctorConfig(t), fakePing{}, &out); code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, out.String())
	}
	for _, want := range []string{"Docker answers", "reached through tcp://guard:2375", "no users yet", "/setup"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, out.String())
		}
	}
}

func TestDoctor_FailsWhenDockerIsDownOrFilesAreNotWritable(t *testing.T) {
	cfg := doctorConfig(t)
	cfg.UsersFile = "/nonexistent-dir/users.env"
	var out strings.Builder
	if code := runDoctor(cfg, fakePing{err: errors.New("no socket")}, &out); code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out.String())
	}
	for _, want := range []string{"FAIL  Docker did not answer: no socket", "FAIL  users file: cannot write in /nonexistent-dir"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, out.String())
		}
	}
}

func TestDoctor_WarnsAboutRawSocketAndInsecureCookies(t *testing.T) {
	cfg := doctorConfig(t)
	cfg.Server.DockerHost = ""
	cfg.Server.SecureCookies = false
	var out strings.Builder
	if code := runDoctor(cfg, fakePing{}, &out); code != 0 {
		t.Fatalf("warnings must not fail the run, exit %d", code)
	}
	for _, want := range []string{"raw Docker socket", "secure_cookies is off"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, out.String())
		}
	}
}

func TestDoctor_ManagedNeedsAPolicy(t *testing.T) {
	cfg := doctorConfig(t)
	cfg.Managed.Dir = t.TempDir()
	cfg.Managed.PolicyFile = filepath.Join(t.TempDir(), "missing.yaml")
	var out strings.Builder
	if code := runDoctor(cfg, fakePing{}, &out); code != 1 || !strings.Contains(out.String(), "policy file:") {
		t.Fatalf("exit %d, want 1 with a policy complaint:\n%s", code, out.String())
	}
}

func TestDoctor_WarnsAboutUnusedPasswordHashes(t *testing.T) {
	cfg := doctorConfig(t)
	if err := os.WriteFile(cfg.UsersFile, []byte("ALEX_PASSWORD_HASH=x\nALEX_ROLE=admin\nALEX_GOOGLE_EMAIL=alex@example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	off := false
	cfg.Auth.PasswordLogin = &off
	cfg.Auth.Google = &config.GoogleAuthConfig{}
	var out strings.Builder
	runDoctor(cfg, fakePing{}, &out)
	if !strings.Contains(out.String(), "still have a stored password hash: alex") {
		t.Errorf("no warning about the stale hash:\n%s", out.String())
	}
	// With password login on, the hash is in use and nothing is said.
	on := true
	cfg.Auth.PasswordLogin = &on
	out.Reset()
	runDoctor(cfg, fakePing{}, &out)
	if strings.Contains(out.String(), "stored password hash") {
		t.Errorf("warned while password login is on:\n%s", out.String())
	}
}

func TestDoctor_BackupsFolder(t *testing.T) {
	cfg := doctorConfig(t)
	mount := t.TempDir()
	cfg.Platform.BackupsRoot, cfg.Platform.BackupsMount, cfg.Platform.BackupsDirMode = "/mnt/usb/backups", mount, "0775"
	run := func() (int, string) {
		var out strings.Builder
		code := runDoctor(cfg, fakePing{}, &out)
		return code, out.String()
	}
	if code, out := run(); code != 1 || !strings.Contains(out, "backups_confirm_new") {
		t.Fatalf("unconfirmed new folder: exit %d\n%s", code, out)
	}
	cfg.Platform.BackupsConfirmNew = true
	if code, out := run(); code != 0 || !strings.Contains(out, "folder is new") || !strings.Contains(out, "0775") {
		t.Fatalf("confirmed new folder: exit %d\n%s", code, out)
	}
	cfg.Platform.BackupsConfirmNew = false
	// Used before, then the drive goes away: empty folder, no marker.
	state := filepath.Join(filepath.Dir(cfg.Server.SettingsFile), "backups-root")
	if err := os.WriteFile(state, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := run(); code != 1 || !strings.Contains(out, "unmounted external drive") {
		t.Fatalf("lost drive: exit %d\n%s", code, out)
	}
	if err := os.WriteFile(filepath.Join(mount, ".crowsnest-backups"), []byte("tok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := run(); code != 0 || !strings.Contains(out, "is the one used before") {
		t.Fatalf("restored drive: exit %d\n%s", code, out)
	}
	cfg.Platform.BackupsMount = filepath.Join(mount, "missing")
	if code, out := run(); code != 1 || !strings.Contains(out, "is not a folder in the panel") {
		t.Fatalf("not mounted: exit %d\n%s", code, out)
	}
}
