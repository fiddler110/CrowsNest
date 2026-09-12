package palworld

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

func newFakeDockerRunning(t *testing.T, running bool) *dockerctl.Client {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "docker")
	script := "#!/bin/sh\necho -n\n"
	if running {
		script = "#!/bin/sh\necho palworld\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	return &dockerctl.Client{DockerBin: path}
}

func requireBasicAuth(t *testing.T, user, pass string, handler http.HandlerFunc) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

func TestCheck_OfflineWhenContainerNotRunning(t *testing.T) {
	c := &Client{Docker: newFakeDockerRunning(t, false)}
	status, err := c.Check(context.Background(), "palworld")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if status != games.StatusOffline {
		t.Errorf("status = %v, want StatusOffline", status)
	}
}

func TestCheck_OnlineWhenRESTAPIResponds(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/api/info", requireBasicAuth(t, "admin", "secret", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"version": "v0.1.5.0", "servername": "test"})
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, User: "admin", Password: "secret", Docker: newFakeDockerRunning(t, true)}
	status, err := c.Check(context.Background(), "palworld")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if status != games.StatusOnline {
		t.Errorf("status = %v, want StatusOnline", status)
	}
}

func TestCheck_StartingWhenRunningButRESTUnreachable(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1", User: "admin", Password: "secret", Docker: newFakeDockerRunning(t, true)}
	status, err := c.Check(context.Background(), "palworld")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if status != games.StatusStarting {
		t.Errorf("status = %v, want StatusStarting", status)
	}
}

func TestPlayerCount_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/api/players", requireBasicAuth(t, "admin", "secret", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"players": []map[string]any{
				{"name": "Alice", "accountName": "alice", "level": 10},
				{"name": "Bob", "accountName": "bob", "level": 5},
			},
		})
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, User: "admin", Password: "secret"}
	count, names, ok := c.PlayerCount(context.Background())
	if !ok {
		t.Fatal("PlayerCount() ok = false, want true")
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	if len(names) != 2 || names[0] != "Alice" || names[1] != "Bob" {
		t.Errorf("names = %v, want [Alice Bob]", names)
	}
}

func TestPlayerCount_WrongCredentialsIsUndeterminable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/api/players", requireBasicAuth(t, "admin", "secret", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"players": []map[string]any{}})
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, User: "admin", Password: "wrong"}
	_, _, ok := c.PlayerCount(context.Background())
	if ok {
		t.Fatal("PlayerCount() ok = true with wrong credentials, want false")
	}
}

func TestPlayerCount_UnreachableIsUndeterminable(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1", User: "admin", Password: "secret"}
	_, _, ok := c.PlayerCount(context.Background())
	if ok {
		t.Fatal("PlayerCount() ok = true for an unreachable server, want false")
	}
}

func TestPlayerCount_EmptyServerReportsZero(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/api/players", requireBasicAuth(t, "admin", "secret", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"players": []map[string]any{}})
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, User: "admin", Password: "secret"}
	count, _, ok := c.PlayerCount(context.Background())
	if !ok {
		t.Fatal("PlayerCount() ok = false, want true")
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}
