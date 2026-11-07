package palworld

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestPrepareStop_AnnouncesToPlayersThenSaves(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	players := 2
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/v1/api/players" {
			fmt.Fprintf(w, `{"players":[%s]}`, strings.TrimSuffix(strings.Repeat(`{"name":"p"},`, players), ","))
			return
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, User: "admin", Password: "x", NoticePause: -1}

	if err := c.PrepareStop(context.Background()); err != nil {
		t.Fatalf("PrepareStop = %v", err)
	}
	if got := strings.Join(calls, ","); got != "POST /v1/api/announce,POST /v1/api/save" {
		t.Fatalf("calls with players aboard = %s, want announce then save", got)
	}

	calls, players = nil, 0
	if err := c.PrepareStop(context.Background()); err != nil {
		t.Fatalf("PrepareStop (empty) = %v", err)
	}
	if got := strings.Join(calls, ","); got != "POST /v1/api/save" {
		t.Fatalf("calls with nobody aboard = %s, want save only", got)
	}
}

func TestConsole_ActionsHitTheRESTAPI(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+" "+string(body))
		if r.URL.Path == "/v1/api/players" {
			io.WriteString(w, `{"players":[{"name":"Ann","userId":"steam_1","level":5,"ping":23.4}]}`)
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, User: "admin", Password: "pw"}

	out, err := c.Run(context.Background(), "players", nil)
	if err != nil || !strings.Contains(out, "Ann  [steam_1]  level 5") {
		t.Fatalf("players = %q, %v", out, err)
	}
	if _, err := c.Run(context.Background(), "kick", map[string]string{"userid": "steam_1", "message": "bye"}); err != nil {
		t.Fatal(err)
	}
	if want := `POST /v1/api/kick {"message":"bye","userid":"steam_1"}`; got[len(got)-1] != want {
		t.Fatalf("kick request = %q, want %q", got[len(got)-1], want)
	}
	for _, bad := range []struct {
		action string
		args   map[string]string
	}{
		{"kick", nil},
		{"announce", map[string]string{"message": ""}},
		{"announce", map[string]string{"message": "line\nbreak"}},
		{"announce", map[string]string{"message": strings.Repeat("x", 201)}},
		{"shutdown", nil}, // lifecycle belongs to CrowsNest
		{"stop", nil},
	} {
		n := len(got)
		if _, err := c.Run(context.Background(), bad.action, bad.args); err == nil {
			t.Errorf("%s %v: want error", bad.action, bad.args)
		}
		if len(got) != n {
			t.Errorf("%s %v: rejected input still reached the server", bad.action, bad.args)
		}
	}
}

func TestConsole_RawNeedsRCONAddr(t *testing.T) {
	if _, err := (&Client{}).Raw(context.Background(), "Info"); err == nil {
		t.Fatal("want error without rcon_addr")
	}
	if _, err := (&Client{RCONAddr: "127.0.0.1:1"}).Raw(context.Background(), "a\nb"); !errors.Is(err, games.ErrBadInput) {
		t.Fatalf("multi-line command: %v", err)
	}
}
