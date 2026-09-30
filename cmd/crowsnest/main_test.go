package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/config"
)

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	newMux(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != "ok" {
		t.Fatalf("GET /healthz body = %q, want %q", got, "ok")
	}
}

func TestHealthcheckAddr(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{":5000", "localhost:5000"},
		{":8080", "localhost:8080"},
		{"0.0.0.0:5000", "localhost:5000"},
		{"[::]:5000", "localhost:5000"},
		{"127.0.0.1:5000", "127.0.0.1:5000"},
		{"192.168.1.5:9000", "192.168.1.5:9000"},
		{"not-a-valid-addr", defaultHealthcheckAddr},
		{"", defaultHealthcheckAddr},
	}
	for _, c := range cases {
		if got := healthcheckAddr(c.addr); got != c.want {
			t.Errorf("healthcheckAddr(%q) = %q, want %q", c.addr, got, c.want)
		}
	}
}

// writeTestConfig writes a minimal valid config.yaml (plus an empty users
// file next to it) under a fresh temp dir, pointing server.addr at addr.
// Returns the config path.
func writeTestConfig(t *testing.T, addr string) string {
	t.Helper()
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "users.env")
	if err := os.WriteFile(usersFile, nil, 0o600); err != nil {
		t.Fatalf("write users file: %v", err)
	}

	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`
server:
  addr: %q
users_file: %q
games:
  - id: test
    display_name: Test
    container_name: test
    compose_file: %q
    compose_profile: test
    compose_service: test
`, addr, usersFile, filepath.Join(dir, "compose.yaml"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

// TestHealthcheckCustomPort is a regression test for healthcheck() having
// once hardcoded "localhost:5000": with server.addr configured to a
// non-default port, healthcheck() must still find and hit /healthz.
func TestHealthcheckCustomPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://") // e.g. "127.0.0.1:54321"

	t.Setenv("CROWSNEST_CONFIG", writeTestConfig(t, addr))

	if got := healthcheck(); got != 0 {
		t.Fatalf("healthcheck() = %d, want 0 (server.addr=%s)", got, addr)
	}
}

func TestHealthcheckUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	t.Setenv("CROWSNEST_CONFIG", writeTestConfig(t, addr))

	if got := healthcheck(); got != 1 {
		t.Fatalf("healthcheck() = %d, want 1 (unhealthy backend)", got)
	}
}

func TestHealthcheckUnreachable(t *testing.T) {
	// Nothing is listening on this address.
	t.Setenv("CROWSNEST_CONFIG", writeTestConfig(t, "127.0.0.1:1"))

	if got := healthcheck(); got != 1 {
		t.Fatalf("healthcheck() = %d, want 1 (nothing listening)", got)
	}
}

// withStdin temporarily replaces os.Stdin with a reader yielding content,
// restoring it after the test.
func withStdin(t *testing.T, content string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if _, err := io.WriteString(w, content); err != nil {
		t.Fatalf("write stdin pipe: %v", err)
	}
	w.Close()

	original := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = original
		r.Close()
	})
}

func TestSetPasswordAndRevokeSessions(t *testing.T) {
	cfgPath := writeTestConfig(t, ":5000")
	t.Setenv("CROWSNEST_CONFIG", cfgPath)

	withStdin(t, "hunter2\n")
	if err := setPassword("Alice"); err != nil {
		t.Fatalf("setPassword: %v", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	users, err := auth.LoadUsers(cfg.UsersFile)
	if err != nil {
		t.Fatalf("LoadUsers: %v", err)
	}
	rec, ok := users["alice"]
	if !ok {
		t.Fatalf("user %q not found after setPassword, got %v", "alice", users)
	}
	if !auth.VerifyPassword(rec.Hash, "hunter2") {
		t.Fatalf("stored hash does not verify against the password just set")
	}
	if !rec.ValidAfter.IsZero() {
		t.Fatalf("ValidAfter should be unset for a freshly created user, got %v", rec.ValidAfter)
	}

	if err := revokeSessions("Alice"); err != nil {
		t.Fatalf("revokeSessions: %v", err)
	}
	users, err = auth.LoadUsers(cfg.UsersFile)
	if err != nil {
		t.Fatalf("LoadUsers after revoke: %v", err)
	}
	if users["alice"].ValidAfter.IsZero() {
		t.Fatalf("ValidAfter should be set after revokeSessions")
	}

	if err := revokeSessions("nobody"); err == nil {
		t.Fatalf("revokeSessions(%q) should fail for an unknown user", "nobody")
	}
}

func TestSetPasswordRejectsEmptyPassword(t *testing.T) {
	t.Setenv("CROWSNEST_CONFIG", writeTestConfig(t, ":5000"))
	withStdin(t, "\n")
	if err := setPassword("bob"); err == nil {
		t.Fatalf("setPassword with an empty password should fail")
	}
}
