package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestGuardRefusesToStartWithoutValidScopes(t *testing.T) {
	for _, env := range []string{"", "not json", "[]", `[{"name": "game"}]`} {
		t.Setenv("GUARD_SCOPES", env)
		err := runGuard([]string{"--listen", "127.0.0.1:0", "--socket", "/nonexistent.sock"})
		if err == nil || !strings.Contains(err.Error(), "refusing to start") {
			t.Errorf("GUARD_SCOPES=%q: err = %v", env, err)
		}
	}
	t.Setenv("GUARD_SCOPES", `[{"name": "game", "images": ["a/b"]}]`)
	t.Setenv("GUARD_MAX_RESPONSE", "-1")
	if err := runGuard([]string{"--listen", "127.0.0.1:0"}); err == nil || !strings.Contains(err.Error(), "refusing to start") {
		t.Errorf("bad GUARD_MAX_RESPONSE: %v", err)
	}
}

// With --exec, one process serves the exec allowlist on the public address and the
// guard behind it on loopback. A fake Docker socket records what gets through.
func TestGuardWithExecAllowlistInOneProcess(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "docker.sock")
	ul, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	fake := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		_, _ = w.Write([]byte("OK"))
	})}
	go fake.Serve(ul)
	defer fake.Close()

	cfgPath := filepath.Join(dir, "config.yaml")
	y := "server:\n  session_secret_file: " + dir + "/s\n  settings_file: " + dir + "/x.json\n  history_file: " + dir + "/e.jsonl\nusers_file: " + dir + "/u.env\ngames:\n  - id: game\n    display_name: G\n    container_name: game\n    compose_file: /data/compose.yaml\n    compose_profile: game\n    compose_service: game\n"
	if err := os.WriteFile(cfgPath, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CROWSNEST_CONFIG", cfgPath)
	t.Setenv("GUARD_SCOPES", `[{"name": "game", "images": ["a/b"], "exec": true}]`)

	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pl.Addr().String()
	pl.Close()

	done := make(chan error, 1)
	go func() { done <- runGuard([]string{"--listen", addr, "--socket", sock, "--exec"}) }()

	var ok bool
	for i := 0; i < 100 && !ok; i++ {
		resp, err := http.Get("http://" + addr + "/_ping")
		if err == nil {
			resp.Body.Close()
			ok = resp.StatusCode == 200
		}
		if !ok {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !ok {
		t.Fatal("the combined guard never answered /_ping")
	}

	// Exec is allowed by the guard's scope but no command is on the allowlist, so the exec layer refuses it
	// before it reaches the guard or Docker.
	resp, err := http.Post("http://"+addr+"/containers/game/exec", "application/json", strings.NewReader(`{"Cmd":["/bin/sh","-c","id"]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("exec of a command not on the allowlist: status %d, want 403", resp.StatusCode)
	}
	mu.Lock()
	for _, s := range seen {
		if strings.Contains(s, "exec") {
			t.Errorf("an exec request reached Docker: %v", seen)
		}
	}
	mu.Unlock()

	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runGuard: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the combined guard did not stop on SIGTERM")
	}
}
