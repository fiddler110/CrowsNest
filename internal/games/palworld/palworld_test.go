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

func TestInfo_MergesInfoAndMetrics(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/api/info", requireBasicAuth(t, "admin", "secret", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"version": "v1.0.5", "servername": "Pals", "description": "", "worldguid": "ABC"})
	}))
	mux.HandleFunc("GET /v1/api/metrics", requireBasicAuth(t, "admin", "secret", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"currentplayernum": 2, "maxplayernum": 8, "serverfps": 59, "serverfpsaverage": 63.15,
			"serverframetime": 16.79, "days": 12, "basecampnum": 3, "uptime": 3700,
		})
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, User: "admin", Password: "secret"}
	got, ok := c.Info(context.Background())
	if !ok {
		t.Fatal("Info() ok = false, want true")
	}
	want := map[string]any{
		"server_name": "Pals", "version": "v1.0.5", "world_id": "ABC",
		"players": "2 / 8", "uptime": "1h 1m", "server_fps": "59 (avg 63)",
		"frame_time_ms": "16.8", "in_game_days": 12, "base_camps": 3,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("Info()[%q] = %v, want %v", k, got[k], v)
		}
	}
	if _, present := got["description"]; present {
		t.Error("empty description should be omitted")
	}
}

func TestInfo_MetricsFailureStillReturnsIdentity(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/api/info", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"version": "v1", "servername": "Pals"})
	})
	srv := httptest.NewServer(mux) // no /metrics route -> 404
	defer srv.Close()

	c := &Client{BaseURL: srv.URL}
	got, ok := c.Info(context.Background())
	if !ok || got["server_name"] != "Pals" {
		t.Fatalf("Info() = %v, %v; want identity fields with ok=true", got, ok)
	}
	if _, present := got["uptime"]; present {
		t.Error("metrics fields should be absent when /metrics fails")
	}
}

func TestInfo_UnreachableIsUnavailable(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1"}
	if _, ok := c.Info(context.Background()); ok {
		t.Fatal("Info() ok = true for unreachable server, want false")
	}
}

func TestFormatUptime(t *testing.T) {
	for secs, want := range map[int64]string{5: "5s", 125: "2m", 3700: "1h 1m", 90000: "1d 1h"} {
		if got := formatUptime(secs); got != want {
			t.Errorf("formatUptime(%d) = %q, want %q", secs, got, want)
		}
	}
}

func TestParseDownload(t *testing.T) {
	pct, label, ok := parseDownload(" Update state (0x61) downloading, progress: 50.00 (2466035288 / 4932070576)")
	if !ok || pct != 47 || label != "Downloading server files (50%)" {
		t.Errorf("parseDownload = %d, %q, %v", pct, label, ok)
	}
	if _, _, ok := parseDownload("Update state (0x5) verifying install, progress: 50.00"); ok {
		t.Error("verifying lines should not match")
	}
}

func TestStartup_MilestonesAscending(t *testing.T) {
	prev := -1
	for _, m := range Startup.Milestones {
		if m.Pct <= prev {
			t.Errorf("milestone %q pct %d not greater than previous %d", m.Label, m.Pct, prev)
		}
		prev = m.Pct
	}
	// Download progress must land between the pre-download and post-download milestones.
	if pct, _, _ := parseDownload("Update state (0x61) downloading, progress: 100.00"); pct >= 86 {
		t.Errorf("100%% download maps to %d, must stay below the post-download milestones", pct)
	}
}
