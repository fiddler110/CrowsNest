package modules

// Characterization of the bundled palworld module. These are the behaviours
// of the former hand-written internal/games/palworld client, now asserted
// against the declarative module.yaml so the move changed nothing.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/dockerctl/dockertest"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/probes"
)

func fakeDocker(t *testing.T, running bool) *dockerctl.Client {
	t.Helper()
	f := dockertest.New(t)
	f.Add("palworld", running)
	return f.Client()
}

// palworldDef wires the bundled module against baseURL.
func palworldDef(t *testing.T, baseURL string, running bool, extra map[string]string) *games.GameDef {
	t.Helper()
	t.Setenv("PW_TEST_PASS", "secret")
	opts := map[string]string{"rest_api_url": baseURL, "rest_api_password_env": "PW_TEST_PASS"}
	for k, v := range extra {
		opts[k] = v
	}
	def := &games.GameDef{ID: "palworld", ContainerName: "palworld"}
	Bundled().wire["palworld"](def, Env{Docker: fakeDocker(t, running), Config: config.GameConfig{Options: opts}})
	if api, ok := def.PreStop.(*probes.HTTPJSON); ok {
		api.Sleep = func(context.Context, time.Duration) {}
	}
	return def
}

func authed(user, pass string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != user || p != pass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func TestPalworld_Status(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/api/info", authed("admin", "secret", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"version": "v1", "servername": "t"})
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for name, c := range map[string]struct {
		def  *games.GameDef
		want games.Status
	}{
		"offline":  {palworldDef(t, srv.URL, false, nil), games.StatusOffline},
		"online":   {palworldDef(t, srv.URL, true, nil), games.StatusOnline},
		"starting": {palworldDef(t, "http://127.0.0.1:1", true, nil), games.StatusStarting},
	} {
		got, err := c.def.Status.Check(context.Background(), "palworld")
		if err != nil || got != c.want {
			t.Errorf("%s: Check = %v, %v; want %v", name, got, err, c.want)
		}
	}
}

func TestPalworld_PlayerCount(t *testing.T) {
	n := 2
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/api/players", authed("admin", "secret", func(w http.ResponseWriter, r *http.Request) {
		ps := []map[string]any{{"name": "Alice"}, {"name": "Bob"}}[:n]
		json.NewEncoder(w).Encode(map[string]any{"players": ps})
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	count, names, ok := palworldDef(t, srv.URL, true, nil).Players.PlayerCount(context.Background())
	if !ok || count != 2 || len(names) != 2 || names[0] != "Alice" || names[1] != "Bob" {
		t.Fatalf("PlayerCount = %d %v %v", count, names, ok)
	}
	n = 0
	if count, _, ok := palworldDef(t, srv.URL, true, nil).Players.PlayerCount(context.Background()); !ok || count != 0 {
		t.Errorf("empty server = %d, %v; want 0, true", count, ok)
	}
	// Wrong password and unreachable are unknown, never zero.
	t.Setenv("PW_WRONG", "nope")
	bad := palworldDef(t, srv.URL, true, map[string]string{"rest_api_password_env": "PW_WRONG"})
	if _, _, ok := bad.Players.PlayerCount(context.Background()); ok {
		t.Error("wrong credentials must be ok=false")
	}
	if _, _, ok := palworldDef(t, "http://127.0.0.1:1", true, nil).Players.PlayerCount(context.Background()); ok {
		t.Error("unreachable must be ok=false")
	}
}

func TestPalworld_Info(t *testing.T) {
	metrics := true
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/api/info", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"version": "v1.0.5", "servername": "Pals", "description": "", "worldguid": "ABC"})
	})
	mux.HandleFunc("GET /v1/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !metrics {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"currentplayernum": 2, "maxplayernum": 8, "serverfps": 59, "serverfpsaverage": 63.15,
			"serverframetime": 16.79, "days": 12, "basecampnum": 3, "uptime": 3700,
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	def := palworldDef(t, srv.URL, true, map[string]string{})

	got, ok := def.Info.Info(context.Background())
	if !ok {
		t.Fatal("Info ok=false")
	}
	for k, v := range map[string]any{
		"server_name": "Pals", "version": "v1.0.5", "world_id": "ABC",
		"players": "2 / 8", "uptime": "1h 1m", "server_fps": "59 (avg 63)",
		"frame_time_ms": "16.8", "in_game_days": 12, "base_camps": 3,
	} {
		if got[k] != v {
			t.Errorf("Info[%q] = %v (%T), want %v", k, got[k], got[k], v)
		}
	}
	if _, present := got["description"]; present {
		t.Error("empty description must be omitted")
	}

	metrics = false
	got, ok = def.Info.Info(context.Background())
	if !ok || got["server_name"] != "Pals" {
		t.Fatalf("metrics failure: %v %v", got, ok)
	}
	if _, present := got["uptime"]; present {
		t.Error("metrics fields must be absent when /metrics fails")
	}
	if _, ok := palworldDef(t, "http://127.0.0.1:1", true, nil).Info.Info(context.Background()); ok {
		t.Error("unreachable Info must be unavailable")
	}
}

func TestPalworld_PrepareStop(t *testing.T) {
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
	def := palworldDef(t, srv.URL, true, nil)

	if err := def.PreStop.PrepareStop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ","); got != "POST /v1/api/announce,POST /v1/api/save" {
		t.Fatalf("with players aboard: %s", got)
	}
	calls, players = nil, 0
	if err := def.PreStop.PrepareStop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ","); got != "POST /v1/api/save" {
		t.Fatalf("with nobody aboard: %s", got)
	}
}

func TestPalworld_Console(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+" "+string(body))
		if r.URL.Path == "/v1/api/players" {
			io.WriteString(w, `{"players":[{"name":"Ann","userId":"steam_1","level":5,"ping":23.4}]}`)
		}
	}))
	defer srv.Close()
	c := palworldDef(t, srv.URL, true, nil).Console

	if ids := actionIDs(c); ids != "players,announce,save,kick,ban,unban" {
		t.Errorf("actions = %s", ids)
	}
	out, err := c.Run(context.Background(), "players", nil)
	if err != nil || !strings.Contains(out, "Ann  [steam_1]  level 5  23 ms") {
		t.Fatalf("players = %q, %v", out, err)
	}
	out, err = c.Run(context.Background(), "kick", map[string]string{"userid": "steam_1", "message": "bye"})
	if err != nil || out != "Kick applied to steam_1." {
		t.Fatalf("kick = %q, %v", out, err)
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
		{"kick", map[string]string{"userid": strings.Repeat("x", 101)}},
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

func actionIDs(c games.Console) string {
	var ids []string
	for _, a := range c.Actions() {
		ids = append(ids, a.ID)
	}
	return strings.Join(ids, ",")
}

func TestPalworld_RawConsoleNeedsRCONAddr(t *testing.T) {
	if def := palworldDef(t, "http://x:1", true, nil); def.RawConsole != nil {
		t.Fatal("raw console must be off without rcon_addr")
	}
	def := palworldDef(t, "http://x:1", true, map[string]string{"rcon_addr": "127.0.0.1:1", "rcon_password_env": "PW_TEST_PASS"})
	if def.RawConsole == nil {
		t.Fatal("raw console must be on with rcon_addr")
	}
	if _, err := def.RawConsole.Raw(context.Background(), "a\nb"); err == nil || !strings.Contains(err.Error(), "one line") {
		t.Fatalf("multi-line command: %v", err)
	}
}

func TestPalworld_NoOptionsKeepsBaselineAndStartup(t *testing.T) {
	def := &games.GameDef{ID: "palworld"}
	Bundled().wire["palworld"](def, Env{})
	if def.Status != nil || def.Players != nil || def.Console != nil {
		t.Error("without options the API must stay unwired")
	}
	if def.RestartCooldown != 30*time.Second || def.Startup == nil {
		t.Errorf("cooldown/startup must apply regardless: %v %v", def.RestartCooldown, def.Startup)
	}
}

func TestPalworld_Startup(t *testing.T) {
	def := &games.GameDef{}
	Bundled().wire["palworld"](def, Env{})
	pct, label, ok := def.Startup.Parse(" Update state (0x61) downloading, progress: 50.00 (2466035288 / 4932070576)")
	if !ok || pct != 47 || label != "Downloading server files (50%)" {
		t.Errorf("download = %d %q %v", pct, label, ok)
	}
	if _, _, ok := def.Startup.Parse("Update state (0x5) verifying install, progress: 50.00"); ok {
		t.Error("verifying lines must not match")
	}
	if pct, _, _ := def.Startup.Parse("Update state (0x61) downloading, progress: 100.00"); pct >= 86 {
		t.Errorf("100%% download = %d, must stay below the post-download milestones", pct)
	}
	prev := -1
	for _, m := range def.Startup.Milestones {
		if m.Pct <= prev {
			t.Errorf("milestone %q not ascending", m.Label)
		}
		prev = m.Pct
	}
}
