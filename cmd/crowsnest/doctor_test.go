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
