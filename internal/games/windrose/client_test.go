package windrose

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
)

// newFakeDockerInspect builds a dockerctl.Client whose `docker inspect
// --format {{.State.StartedAt}}` reports startedAt, for isStale/uptime
// tests that need a container start time without a real container.
func newFakeDockerInspect(t *testing.T, startedAt time.Time) *dockerctl.Client {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "docker")
	script := fmt.Sprintf("#!/bin/sh\necho '%s'\n", startedAt.UTC().Format(time.RFC3339Nano))
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	return &dockerctl.Client{DockerBin: path}
}

// fakeWplusServer builds an httptest.Server standing in for the Windrose+
// HTTP API: POST /login sets the wp_session cookie when the posted password
// matches wantPassword; GET /api/status and POST /api/rcon require it.
// handlers may mutate shared state (e.g. call counts) across requests.
type fakeWplusServer struct {
	*httptest.Server
	wantPassword string
	statusCalls  int
	rconCalls    int

	// statusFunc, if set, is called for each valid /api/status request and
	// its return value is marshaled as the response body.
	statusFunc func(call int) map[string]any
	// rconFunc, if set, is called for each valid /api/rcon request.
	rconFunc func(command string) (message string, ok bool)

	loginFails    bool
	rejectCookies bool // when true, every authenticated request reports "Authentication required"
}

func newFakeWplusServer(t *testing.T, password string) *fakeWplusServer {
	t.Helper()
	f := &fakeWplusServer{wantPassword: password}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		if f.loginFails {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil || r.FormValue("password") != f.wantPassword {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "wp_session", Value: "sess-token"})
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		if !f.hasValidCookie(r) {
			json.NewEncoder(w).Encode(map[string]string{"error": "Authentication required"})
			return
		}
		f.statusCalls++
		var body map[string]any
		if f.statusFunc != nil {
			body = f.statusFunc(f.statusCalls)
		} else {
			body = map[string]any{"mode": "active"}
		}
		json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("POST /api/rcon", func(w http.ResponseWriter, r *http.Request) {
		if !f.hasValidCookie(r) {
			json.NewEncoder(w).Encode(map[string]string{"error": "Authentication required"})
			return
		}
		f.rconCalls++
		var req struct {
			Command string `json:"command"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if f.rconFunc != nil {
			msg, ok := f.rconFunc(req.Command)
			if !ok {
				json.NewEncoder(w).Encode(map[string]string{"status": "error"})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": msg})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": ""})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

func (f *fakeWplusServer) hasValidCookie(r *http.Request) bool {
	if f.rejectCookies {
		return false
	}
	ck, err := r.Cookie("wp_session")
	return err == nil && ck.Value == "sess-token"
}

func newTestClient(baseURL, password string, docker *dockerctl.Client) *Client {
	return &Client{
		BaseURL:       baseURL,
		Password:      password,
		Docker:        docker,
		ContainerName: "windrose",
	}
}

func TestPlayerCount_ActiveMode(t *testing.T) {
	srv := newFakeWplusServer(t, "secret")
	srv.statusFunc = func(int) map[string]any {
		return map[string]any{
			"mode":      "active",
			"timestamp": float64(time.Now().Unix()),
			"server":    map[string]any{"windrose_plus": "1.2.3", "player_count": 2},
			"players": []map[string]any{
				{"name": "Alice", "x": 1.0, "y": 2.0, "z": 3.0},
				{"name": "Bob"},
			},
		}
	}
	docker := newFakeDockerInspect(t, time.Now().Add(-time.Hour))
	c := newTestClient(srv.URL, "secret", docker)

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

func TestPlayerCount_BootModeIsUndeterminable(t *testing.T) {
	srv := newFakeWplusServer(t, "secret")
	srv.statusFunc = func(int) map[string]any {
		return map[string]any{"mode": "boot", "timestamp": float64(time.Now().Unix())}
	}
	docker := newFakeDockerInspect(t, time.Now().Add(-time.Hour))
	c := newTestClient(srv.URL, "secret", docker)

	_, _, ok := c.PlayerCount(context.Background())
	if ok {
		t.Fatal("PlayerCount() ok = true in boot mode, want false")
	}
}

func TestPlayerCount_LoginFailureIsUndeterminable(t *testing.T) {
	srv := newFakeWplusServer(t, "secret")
	srv.loginFails = true
	docker := newFakeDockerInspect(t, time.Now())
	c := newTestClient(srv.URL, "wrong-password", docker)

	_, _, ok := c.PlayerCount(context.Background())
	if ok {
		t.Fatal("PlayerCount() ok = true despite login failure, want false")
	}
}

func TestPlayerCount_StaleDataIsUndeterminable(t *testing.T) {
	srv := newFakeWplusServer(t, "secret")
	srv.statusFunc = func(int) map[string]any {
		return map[string]any{
			"mode":      "active",
			"timestamp": float64(1000), // long before the container's StartedAt below
			"server":    map[string]any{"player_count": 5},
		}
	}
	docker := newFakeDockerInspect(t, time.Now())
	c := newTestClient(srv.URL, "secret", docker)

	_, _, ok := c.PlayerCount(context.Background())
	if ok {
		t.Fatal("PlayerCount() ok = true for stale data, want false")
	}
}

func TestPlayerCount_DegradedModeFallsBackToRCON(t *testing.T) {
	srv := newFakeWplusServer(t, "secret")
	srv.statusFunc = func(int) map[string]any {
		return map[string]any{
			"mode":      "degraded",
			"timestamp": float64(time.Now().Unix()),
			"server":    map[string]any{"player_count": 0},
		}
	}
	srv.rconFunc = func(command string) (string, bool) {
		if command == "wp.connections" {
			return "Active: 3, Zombie Controllers: 0, Mode: normal, Last Player: Alice", true
		}
		return "", false
	}
	docker := newFakeDockerInspect(t, time.Now().Add(-time.Hour))
	c := newTestClient(srv.URL, "secret", docker)

	count, _, ok := c.PlayerCount(context.Background())
	if !ok {
		t.Fatal("PlayerCount() ok = false, want true")
	}
	if count != 3 {
		t.Errorf("count = %d, want 3 (from RCON fallback)", count)
	}
}

func TestStatus_CachedWithinTTL(t *testing.T) {
	srv := newFakeWplusServer(t, "secret")
	docker := newFakeDockerInspect(t, time.Now())
	c := newTestClient(srv.URL, "secret", docker)

	c.status(context.Background())
	c.status(context.Background())
	if srv.statusCalls != 1 {
		t.Errorf("statusCalls = %d, want 1 (second call should be cache-served)", srv.statusCalls)
	}
}

func TestStatus_ReLoginsOnRejectedCookie(t *testing.T) {
	srv := newFakeWplusServer(t, "secret")
	docker := newFakeDockerInspect(t, time.Now())
	c := newTestClient(srv.URL, "secret", docker)

	// Force an initial (now-invalid) cookie so the first /api/status call
	// gets rejected and must re-login.
	c.cookie = "stale-token"
	c.cookieExpires = time.Now().Add(time.Hour)

	data := c.status(context.Background())
	if data == nil {
		t.Fatal("status() = nil, want a re-login recovering the session")
	}
}

func TestInfo_ReportsMultipliersAndRCONFields(t *testing.T) {
	srv := newFakeWplusServer(t, "secret")
	srv.statusFunc = func(int) map[string]any {
		return map[string]any{
			"mode":      "active",
			"timestamp": float64(time.Now().Unix()),
			"server":    map[string]any{"windrose_plus": "1.0.0", "player_count": 1},
			"players":   []map[string]any{{"name": "Alice", "x": 10.4, "y": -3.6, "z": 0.0}},
			"multipliers": map[string]any{
				"loot": 2.0, "xp": 1.5,
			},
		}
	}
	srv.rconFunc = func(command string) (string, bool) {
		switch command {
		case "wp.time":
			return "TimeOfDay = 0.5 DayCycleDuration = 1200 NightCycleDuration = 600", true
		case "wp.weather":
			return "WindSpeed = 3.2 WaveHeight = 1.1 TemperatureMultiplier = 1.0", true
		case "wp.connections":
			return "Active: 1, Zombie Controllers: 0, Mode: normal, Last Player: Alice", true
		case "wp.memory":
			return "Working Set: 1,024 MB Virtual: 2,048 MB Page File: 512 MB", true
		}
		return "", false
	}
	docker := newFakeDockerInspect(t, time.Now().Add(-30*time.Minute))
	c := newTestClient(srv.URL, "secret", docker)

	info, ok := c.Info(context.Background())
	if !ok {
		t.Fatal("Info() ok = false, want true")
	}
	if info["available"] != true {
		t.Errorf("available = %v, want true", info["available"])
	}
	if info["version"] != "1.0.0" {
		t.Errorf("version = %v, want 1.0.0", info["version"])
	}
	mults, _ := info["multipliers"].(map[string]float64)
	if mults["loot"] != 2.0 || mults["xp"] != 1.5 {
		t.Errorf("multipliers = %v, want loot=2 xp=1.5", mults)
	}
	if info["time_of_day"] != 0.5 {
		t.Errorf("time_of_day = %v, want 0.5", info["time_of_day"])
	}
	if info["connections_active"] != 3 && info["connections_active"] != 1 {
		t.Errorf("connections_active = %v", info["connections_active"])
	}
	if info["memory_working_set"] != "1,024 MB" {
		t.Errorf("memory_working_set = %v, want '1,024 MB'", info["memory_working_set"])
	}
	if info["uptime"] == nil {
		t.Error("uptime = nil, want a value derived from container StartedAt")
	}
}

func TestInfo_BootModeSkipsRCON(t *testing.T) {
	srv := newFakeWplusServer(t, "secret")
	srv.statusFunc = func(int) map[string]any {
		return map[string]any{"mode": "boot", "timestamp": float64(time.Now().Unix())}
	}
	docker := newFakeDockerInspect(t, time.Now())
	c := newTestClient(srv.URL, "secret", docker)

	info, ok := c.Info(context.Background())
	if !ok {
		t.Fatal("Info() ok = false, want true")
	}
	if info["available"] != true {
		t.Errorf("available = %v, want true (API reachable, just in boot mode)", info["available"])
	}
	if srv.rconCalls != 0 {
		t.Errorf("rconCalls = %d, want 0 in boot mode", srv.rconCalls)
	}
}

func TestInfo_UnreachableAPIReportsUnavailable(t *testing.T) {
	docker := newFakeDockerInspect(t, time.Now())
	c := newTestClient("http://127.0.0.1:1", "secret", docker) // nothing listens here

	info, ok := c.Info(context.Background())
	if !ok {
		t.Fatal("Info() ok = false, want true (Info itself never errors)")
	}
	if info["available"] != false {
		t.Errorf("available = %v, want false", info["available"])
	}
}
