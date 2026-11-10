package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/backup"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/exclusivity"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/history"
	"github.com/fiddler110/crowsnest/internal/managed"
	"github.com/fiddler110/crowsnest/internal/settings"
)

// testHarness bundles an App with a pre-authenticated session cookie and
// its CSRF token, so tests can exercise protected routes directly.
type testHarness struct {
	App       *App
	Cookie    *http.Cookie
	CSRFToken string
}

func newHarness(t *testing.T, dockerScript string, gameIDs ...string) *testHarness {
	t.Helper()
	if len(gameIDs) == 0 {
		gameIDs = []string{"windrose"}
	}

	docker := fakeDockerClient(t, dockerScript)

	defs := make([]games.GameDef, len(gameIDs))
	for i, id := range gameIDs {
		defs[i] = games.GameDef{
			ID:            id,
			DisplayName:   id,
			ContainerName: id,
			Status:        &games.DockerStatusChecker{Docker: docker},
			Players:       games.UnknownPlayerCounter{},
		}
	}
	return newHarnessFromDefs(t, docker, defs)
}

// fakeDockerClient writes dockerScript to a temp file and returns a Client
// pointed at it.
func fakeDockerClient(t *testing.T, dockerScript string) *dockerctl.Client {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "docker")
	if err := os.WriteFile(binPath, []byte(dockerScript), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	return &dockerctl.Client{DockerBin: binPath}
}

// newHarnessFromDefs is newHarness's shared core, for tests that need
// GameDefs newHarness can't build (e.g. a non-nil Startup matcher).
func newHarnessFromDefs(t *testing.T, docker *dockerctl.Client, defs []games.GameDef) *testHarness {
	t.Helper()
	registry, err := games.NewRegistry(defs)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	templates, err := LoadTemplates()
	if err != nil {
		t.Fatalf("LoadTemplates() error = %v", err)
	}

	sessions := auth.NewSessionManager([]byte("test-secret"), time.Hour)
	excl := exclusivity.NewManager(registry, docker)
	t.Cleanup(excl.Wait) // no background start may outlive the fake docker
	app := &App{
		Registry:    registry,
		Docker:      docker,
		Exclusivity: excl,
		Auth: &auth.Service{
			Users:        auth.Users{},
			Sessions:     sessions,
			LoginLimiter: auth.NewLimiter(1000, time.Minute),
		},
		Templates: templates,
	}

	session, err := sessions.New("tester")
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	token, err := sessions.Encode(session)
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}

	return &testHarness{
		App:       app,
		Cookie:    &http.Cookie{Name: auth.SessionCookieName, Value: token},
		CSRFToken: session.CSRFToken,
	}
}

func (h *testHarness) mux() http.Handler {
	mux := http.NewServeMux()
	h.App.Routes(mux)
	return mux
}

// req builds an authenticated (cookie present) request, optionally with a
// JSON body.
func (h *testHarness) req(method, path string, body []byte) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.AddCookie(h.Cookie)
	return r
}

// authedReq is req plus the CSRF header, for state-changing requests.
func (h *testHarness) authedReq(method, path string, body []byte) *http.Request {
	r := h.req(method, path, body)
	r.Header.Set("X-CSRF-Token", h.CSRFToken)
	return r
}

type fakeIdleTimer struct{ left time.Duration }

func (f fakeIdleTimer) IdleRemaining(string) (time.Duration, bool) { return f.left, true }

func TestListGames_IdleCountdownOnlyWhenOnline(t *testing.T) {
	for _, tc := range []struct {
		running string
		want    bool
	}{{"windrose", true}, {"", false}} {
		t.Setenv("RUNNING_CONTAINER", tc.running)
		h := newHarness(t, psOnlyRunning)
		h.App.IdleTimer = fakeIdleTimer{left: 90 * time.Second}
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games", nil))
		body := rec.Body.String()
		if online := strings.Contains(body, `"status":"online"`); online != tc.want {
			t.Fatalf("running=%q: online=%v, want %v: %s", tc.running, online, tc.want, body)
		}
		if has := strings.Contains(body, `"idle_seconds_left":90`); has != tc.want {
			t.Fatalf("running=%q: countdown present=%v, want %v: %s", tc.running, has, tc.want, body)
		}
	}
}

func TestSettingsAPI(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	store, err := settings.New(settings.Values{IdleEnabled: true, IdleMinutes: 15, NightStartHour: 23, NightEndHour: 5, MaxActiveGames: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	h.App.Settings = store

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/settings", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"idle_minutes":15`) {
		t.Fatalf("GET = %d %s", rec.Code, rec.Body)
	}

	// Partial update changes only what it names.
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.authedReq(http.MethodPut, "/api/settings", []byte(`{"idle_minutes":20,"auto_update":true}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body)
	}
	if v := store.Get(); v.IdleMinutes != 20 || !v.AutoUpdate || !v.IdleEnabled {
		t.Fatalf("store = %+v", v)
	}

	// Invalid and unknown fields are rejected without changing anything.
	for _, body := range []string{`{"idle_minutes":0}`, `{"bogus":1}`} {
		rec = httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq(http.MethodPut, "/api/settings", []byte(body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("PUT %s = %d, want 400", body, rec.Code)
		}
	}
	if store.Get().IdleMinutes != 20 {
		t.Fatal("rejected update changed the store")
	}

	// CSRF is required to change settings.
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodPut, "/api/settings", []byte(`{"idle_minutes":30}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("PUT without CSRF = %d, want 403", rec.Code)
	}
}

const psOnlyRunning = `#!/bin/sh
if [ "$1" = "ps" ] && [ "$2" != "-a" ]; then
  case "$*" in *"name=^$RUNNING_CONTAINER\$"*) echo "$RUNNING_CONTAINER" ;; esac
fi
exit 0
`

func TestHandleListGames(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\n[ \"$1\" = ps ] && echo windrose\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/games = %d, want %d", rec.Code, http.StatusOK)
	}
	var out []gameSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out) != 1 || out[0].ID != "windrose" || out[0].Status != "online" {
		t.Fatalf("body = %+v, want one online windrose entry", out)
	}
}

func TestHandleListGames_Unauthenticated(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/games", nil)) // no cookie

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/games without a session = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleStatus_Offline(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\n[ \"$1\" = ps ] && :\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/windrose/status", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["status"] != "offline" {
		t.Fatalf("status = %q, want offline", body["status"])
	}
}

func TestHandleStatus_UnknownGame(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/palworld/status", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET status for unregistered game = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleStart(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\ncase \"$1\" in\n  ps) echo windrose ;;\n  start) exit 0 ;;\nesac\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.authedReq(http.MethodPost, "/api/games/windrose/start", nil))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST start = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body)
	}
}

func TestHandleStart_MissingCSRF(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodPost, "/api/games/windrose/start", nil)) // cookie, no csrf header

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST start without csrf = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestHandleStart_Conflict(t *testing.T) {
	t.Setenv("RUNNING_CONTAINER", "valheim")
	h := newHarness(t, psOnlyRunning, "windrose", "valheim")

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.authedReq(http.MethodPost, "/api/games/windrose/start", nil))

	if rec.Code != http.StatusConflict {
		t.Fatalf("POST start while valheim active = %d, want %d, body=%s", rec.Code, http.StatusConflict, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["active_game"] != "valheim" {
		t.Fatalf("active_game = %v, want valheim", body["active_game"])
	}
}

func TestHandleStop(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\n[ \"$1\" = stop ] && exit 0\nexit 1\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.authedReq(http.MethodPost, "/api/games/windrose/stop", nil))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST stop = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body)
	}
}

func TestHandleSwitch(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state")
	os.WriteFile(statePath, []byte("valheim\n"), 0o644)
	t.Setenv("FAKE_DOCKER_STATE", statePath)
	t.Setenv("EXISTING", "windrose")

	script := `#!/bin/sh
case "$1" in
  start)
    name="$2"
    grep -qx "$name" "$FAKE_DOCKER_STATE" 2>/dev/null || echo "$name" >> "$FAKE_DOCKER_STATE"
    exit 0
    ;;
  stop)
    name="$2"
    grep -vx "$name" "$FAKE_DOCKER_STATE" > "$FAKE_DOCKER_STATE.tmp" 2>/dev/null
    mv "$FAKE_DOCKER_STATE.tmp" "$FAKE_DOCKER_STATE"
    exit 0
    ;;
  ps)
    if [ "$2" = "-a" ]; then
      candidates="$EXISTING $(cat "$FAKE_DOCKER_STATE" 2>/dev/null)"
    else
      candidates="$(cat "$FAKE_DOCKER_STATE" 2>/dev/null)"
    fi
    for n in $candidates; do
      case "$*" in *"name=^$n\$"*) echo "$n"; break ;; esac
    done
    ;;
esac
`
	h := newHarness(t, script, "windrose", "valheim")
	h.App.Exclusivity.StopPollInterval = time.Millisecond
	h.App.Exclusivity.StopPollTimeout = time.Second

	body, _ := json.Marshal(switchRequest{From: "valheim"})
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.authedReq(http.MethodPost, "/api/games/windrose/switch", body))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST switch = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body)
	}
}

func TestHandleSwitch_BodyTooLarge(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n", "windrose", "valheim")

	oversized := bytes.Repeat([]byte(" "), maxSwitchBodyBytes+1)
	body := append([]byte(`{"from":"valheim","pad":"`), append(oversized, []byte(`"}`)...)...)

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.authedReq(http.MethodPost, "/api/games/windrose/switch", body))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST oversized switch body = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body)
	}
}

func TestHandleStats(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\n[ \"$1\" = stats ] && printf '12.34%%\\t100MiB / 512MiB\\t19.53%%\\n'\n")
	// nvidia-smi is unset -> defaults to the "nvidia-smi" binary, which
	// won't exist on the test host; GPUStats should degrade to ok=false
	// rather than erroring the whole endpoint.
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/windrose/stats", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET stats = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body)
	}
	var body statsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.CPU == nil || *body.CPU != "12.34" {
		t.Fatalf("cpu = %v, want 12.34", body.CPU)
	}
	if body.MemUsed == nil || *body.MemUsed != "100MiB" {
		t.Fatalf("mem_used = %v, want 100MiB", body.MemUsed)
	}
	if body.GPUUtil != nil {
		t.Fatalf("gpu_util = %v, want nil (no GPU on test host)", *body.GPUUtil)
	}
}

func TestHandleStats_ContainerNotRunning(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 1\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/windrose/stats", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET stats = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body)
	}
	var body statsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.CPU != nil {
		t.Fatalf("cpu = %v, want nil when docker stats fails", *body.CPU)
	}
}

func TestHandleStats_UnknownGame(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/palworld/stats", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET stats for unregistered game = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// fakePlayerCounter reports a fixed count/ok pair, for tests that need a
// determinable (or deliberately undeterminable) PlayerCounter.
type fakePlayerCounter struct {
	count int
	names []string
	ok    bool
}

func (f fakePlayerCounter) PlayerCount(context.Context) (int, []string, bool) {
	return f.count, f.names, f.ok
}

// fakeInfoProvider reports fixed Info data/ok, for tests exercising
// games.InfoProvider.
type fakeInfoProvider struct {
	data map[string]any
	ok   bool
}

func (f fakeInfoProvider) Info(context.Context) (map[string]any, bool) {
	return f.data, f.ok
}

func TestHandleListGames_IncludesPlayerCount(t *testing.T) {
	docker := fakeDockerClient(t, "#!/bin/sh\n[ \"$1\" = ps ] && echo windrose\n")
	defs := []games.GameDef{
		{
			ID: "windrose", DisplayName: "windrose", ContainerName: "windrose",
			Status:  &games.DockerStatusChecker{Docker: docker},
			Players: fakePlayerCounter{count: 3, ok: true},
		},
		{
			ID: "valheim", DisplayName: "valheim", ContainerName: "valheim",
			Status:  &games.DockerStatusChecker{Docker: docker},
			Players: fakePlayerCounter{ok: false},
		},
	}
	h := newHarnessFromDefs(t, docker, defs)

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games", nil))

	var body []gameSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body[0].PlayerCount == nil || *body[0].PlayerCount != 3 {
		t.Fatalf("windrose player_count = %v, want 3", body[0].PlayerCount)
	}
	if body[1].PlayerCount != nil {
		t.Fatalf("valheim player_count = %v, want nil (undeterminable)", *body[1].PlayerCount)
	}
}

func TestHandlePlayers_Available(t *testing.T) {
	docker := fakeDockerClient(t, "#!/bin/sh\nexit 0\n")
	defs := []games.GameDef{{
		ID: "windrose", DisplayName: "windrose", ContainerName: "windrose",
		Players: fakePlayerCounter{count: 2, names: []string{"Alice", "Bob"}, ok: true},
	}}
	h := newHarnessFromDefs(t, docker, defs)

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/windrose/players", nil))

	var body playersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !body.Available || body.Count != 2 || len(body.Names) != 2 {
		t.Fatalf("players = %+v, want available with count=2", body)
	}
}

func TestHandlePlayers_Undeterminable(t *testing.T) {
	docker := fakeDockerClient(t, "#!/bin/sh\nexit 0\n")
	defs := []games.GameDef{{
		ID: "windrose", DisplayName: "windrose", ContainerName: "windrose",
		Players: fakePlayerCounter{ok: false},
	}}
	h := newHarnessFromDefs(t, docker, defs)

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/windrose/players", nil))

	var body playersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Available {
		t.Fatalf("players = %+v, want available=false", body)
	}
}

func TestHandlePlayers_NoPlayerCounterWired(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	// newHarness wires games.UnknownPlayerCounter{}, which always reports
	// ok=false — confirm that surfaces as unavailable, not an error.
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/windrose/players", nil))

	var body playersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Available {
		t.Fatalf("players = %+v, want available=false", body)
	}
}

func TestHandleInfo_Available(t *testing.T) {
	docker := fakeDockerClient(t, "#!/bin/sh\nexit 0\n")
	defs := []games.GameDef{{
		ID: "windrose", DisplayName: "windrose", ContainerName: "windrose",
		Info: fakeInfoProvider{data: map[string]any{"available": true, "uptime": "1h"}, ok: true},
	}}
	h := newHarnessFromDefs(t, docker, defs)

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/windrose/info", nil))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["available"] != true || body["uptime"] != "1h" {
		t.Fatalf("info = %v, want available=true uptime=1h", body)
	}
}

// Regression: Palworld's provider returned plain fields with no "available"
// key, and the dashboard (which keys off it) showed "no info" forever even
// though the data was there. The handler now supplies it on success.
func TestHandleInfo_MarksSuccessfulProviderAvailable(t *testing.T) {
	docker := fakeDockerClient(t, "#!/bin/sh\nexit 0\n")
	provider := fakeInfoProvider{data: map[string]any{"server_name": "Pals"}, ok: true}
	defs := []games.GameDef{{ID: "palworld", DisplayName: "palworld", ContainerName: "palworld", Info: provider}}
	h := newHarnessFromDefs(t, docker, defs)

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/palworld/info", nil))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["available"] != true || body["server_name"] != "Pals" {
		t.Fatalf("info = %v, want available=true server_name=Pals", body)
	}
	if _, mutated := provider.data["available"]; mutated {
		t.Error("handler must not mutate the provider's own map")
	}
}

func TestHandleInfo_NoInfoProviderWired(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/windrose/info", nil))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["available"] != false {
		t.Fatalf("info = %v, want available=false", body)
	}
}

func TestHandleDashboard_RedirectsWhenUnauthenticated(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("GET / unauthenticated = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("Location = %q, want /login", loc)
	}
}

func TestHandleDashboard_Authenticated(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\n[ \"$1\" = ps ] && echo windrose\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / authenticated = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "windrose") {
		t.Fatalf("dashboard body does not mention the configured game: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), h.CSRFToken) {
		t.Fatal("dashboard body does not embed the session's CSRF token")
	}
}

// A dashboard load must not wait on probes: with no cached snapshot it
// renders the neutral "checking" badge without ever calling the status
// checker (here a docker that would hang).
func TestHandleDashboard_DoesNotBlockOnProbes(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nsleep 5\n")
	rec := httptest.NewRecorder()
	start := time.Now()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/", nil))
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("dashboard took %v; first paint must not wait on probes", d)
	}
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `data-status="unknown"`) || !strings.Contains(body, "checking") {
		t.Fatalf("want unknown/checking badge, got %d: %s", rec.Code, body)
	}
}

func TestHandleLoginPage(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestLoginLogoutFlow(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\n[ \"$1\" = ps ] && echo windrose\n")
	hash, err := auth.HashPassword("s3cret-pw")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	h.App.Auth.Users["tester"] = auth.UserRecord{Hash: hash}

	loginBody, _ := json.Marshal(map[string]string{"username": "tester", "password": "s3cret-pw"})
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(loginBody)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /login = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies after login = %+v, want exactly one", cookies)
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/games", nil)
	req2.AddCookie(cookies[0])
	h.mux().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET /api/games with fresh login cookie = %d, want %d", rec2.Code, http.StatusOK)
	}

	rec3 := httptest.NewRecorder()
	h.mux().ServeHTTP(rec3, httptest.NewRequest(http.MethodPost, "/logout", nil))
	if rec3.Code != http.StatusOK {
		t.Fatalf("POST /logout = %d, want %d", rec3.Code, http.StatusOK)
	}
}

// A start is accepted immediately (202) and runs in the background; while
// it's in flight the game reports "starting" even though docker doesn't
// show the container running yet, and a failure surfaces on /api/games.
func TestHandleStart_AsyncStatusAndError(t *testing.T) {
	gate := filepath.Join(t.TempDir(), "gate")
	t.Setenv("GATE", gate)
	h := newHarness(t, `#!/bin/sh
case "$1" in
  ps) if [ "$2" = "-a" ]; then echo windrose; fi ;;
  start)
    while [ ! -e "$GATE" ]; do sleep 0.05; done
    echo "pull access denied" >&2; exit 1 ;;
esac
`)
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.authedReq(http.MethodPost, "/api/games/windrose/start", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST start = %d, want 202, body=%s", rec.Code, rec.Body)
	}

	list := func() gameSummary {
		t.Helper()
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games", nil))
		var out []gameSummary
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out) != 1 {
			t.Fatalf("GET /api/games = %s (%v)", rec.Body, err)
		}
		return out[0]
	}
	if g := list(); g.Status != "starting" || g.StartError != "" {
		t.Fatalf("while start in flight: %+v, want status starting and no error", g)
	}

	os.WriteFile(gate, nil, 0o644)
	h.App.Exclusivity.Wait()
	g := list()
	if g.Status != "offline" || !strings.Contains(g.StartError, "pull access denied") || g.StartErrorAt == 0 {
		t.Fatalf("after failed start: %+v, want offline with the docker error", g)
	}
}

func TestHandleDashboard_ConnectDetails(t *testing.T) {
	docker := fakeDockerClient(t, "#!/bin/sh\nexit 0\n")
	mk := func(id, addr, note string) games.GameDef {
		return games.GameDef{
			ID: id, DisplayName: id, ContainerName: id,
			Status:         &games.DockerStatusChecker{Docker: docker},
			Players:        games.UnknownPlayerCounter{},
			ConnectAddress: addr, ConnectNote: note,
		}
	}
	h := newHarnessFromDefs(t, docker, []games.GameDef{
		mk("palworld", "play.example.com:8211", "Password is in <our> chat"),
		mk("valheim", "", ""),
	})
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `data-copy="play.example.com:8211"`) {
		t.Errorf("dashboard missing copy button for the address: %s", body)
	}
	if !strings.Contains(body, "Password is in &lt;our&gt; chat") {
		t.Error("dashboard missing HTML-escaped connect note")
	}
	if n := strings.Count(body, `class="connect"`); n != 1 {
		t.Errorf("connect blocks = %d, want 1 (none for the game without details)", n)
	}
}

func TestHandleDashboard_ConnectSecrets(t *testing.T) {
	docker := fakeDockerClient(t, "#!/bin/sh\nexit 0\n")
	h := newHarnessFromDefs(t, docker, []games.GameDef{{
		ID: "palworld", DisplayName: "Palworld", ContainerName: "palworld",
		Status:         &games.DockerStatusChecker{Docker: docker},
		Players:        games.UnknownPlayerCounter{},
		ConnectSecrets: []games.ConnectSecret{{Label: "Join password", Value: `pa"ss<1>`}},
	}})
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "Join password") || !strings.Contains(body, `data-copy="pa&#34;ss&lt;1&gt;"`) {
		t.Errorf("dashboard missing escaped secret with copy button: %s", body)
	}
}

// A user's start request reaches the notifier with their session username.
func TestHandleStart_NotifiesWithActor(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	n := &chanNotifier{ch: make(chan string, 4)}
	h.App.Exclusivity.Notifier = n

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.authedReq(http.MethodPost, "/api/games/windrose/start", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start = %d, want 202", rec.Code)
	}
	select {
	case msg := <-n.ch:
		if !strings.Contains(msg, "requested by tester") {
			t.Errorf("message = %q, want it to name the session user", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no notification received")
	}
}

type chanNotifier struct{ ch chan string }

func (c *chanNotifier) Notify(_ context.Context, m string) { c.ch <- m }

func TestLoginPage_GoogleOnly(t *testing.T) {
	h := newHarness(t, psOnlyRunning, "palworld")
	h.App.Auth.DisablePasswordLogin = true
	h.App.Google = &auth.GoogleLogin{RedirectURL: "https://crowsnest.example.com/auth/google/callback", Service: h.App.Auth}

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login?error="+auth.LoginErrorNotAllowed, nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(body, `href="https://crowsnest.example.com/auth/google/start"`) {
		t.Fatal("login page has no Google sign-in link to the redirect URL's origin")
	}
	if strings.Contains(body, `id="login-form"`) || strings.Contains(body, "login.js") {
		t.Fatal("password form still rendered with password sign-in disabled")
	}
	if !strings.Contains(body, "crew list") {
		t.Fatal("not-allowed error message not shown")
	}

	// The Google routes are registered; an unknown error code shows nothing.
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, auth.GoogleStartPath, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("GET %s = %d, want 302", auth.GoogleStartPath, rec.Code)
	}
	// HEAD would otherwise reach the callback (Go's GET pattern matches it) and burn the state cookie.
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodHead, auth.GoogleCallbackPath+"?code=x&state=y", nil))
	if rec.Code != http.StatusMethodNotAllowed || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("HEAD %s = %d with cookies %v, want 405 and no cookie changes", auth.GoogleCallbackPath, rec.Code, rec.Result().Cookies())
	}
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login?error=%3Cscript%3E", nil))
	if strings.Contains(rec.Body.String(), "<script>") || !strings.Contains(rec.Body.String(), `id="login-alert" role="alert" hidden`) {
		t.Fatal("an unknown error code must not render any text")
	}
}

func TestLoginPage_PasswordOnlyByDefault(t *testing.T) {
	h := newHarness(t, psOnlyRunning, "palworld")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `id="login-form"`) || strings.Contains(body, "Sign in with Google") {
		t.Fatal("default login page should show the password form and no Google button")
	}
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, auth.GoogleStartPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET %s without Google configured = %d, want 404", auth.GoogleStartPath, rec.Code)
	}
}

type countingStatus struct{ calls atomic.Int32 }

func (c *countingStatus) Check(context.Context, string) (games.Status, error) {
	c.calls.Add(1)
	return games.StatusOffline, nil
}

// Many tabs polling at once must cost one status probe per game, not one
// per request.
func TestListGames_SharesProbesAcrossRequests(t *testing.T) {
	docker := fakeDockerClient(t, "#!/bin/sh\nexit 0\n")
	cs := &countingStatus{}
	h := newHarnessFromDefs(t, docker, []games.GameDef{
		{ID: "a", DisplayName: "a", ContainerName: "a", Status: cs},
	})
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.mux().ServeHTTP(rec, h.req("GET", "/api/games", nil))
			if rec.Code != http.StatusOK {
				t.Errorf("GET /api/games = %d", rec.Code)
			}
		}()
	}
	wg.Wait()
	if n := cs.calls.Load(); n != 1 {
		t.Fatalf("status checked %d times for 25 concurrent polls, want 1", n)
	}
}

// An accepted stop must show immediately, not after the cache expires.
func TestStop_ReportsStoppingImmediately(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\ncase \"$1\" in ps) echo windrose ;; stop) sleep 1 ;; esac\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req("GET", "/api/games/windrose/status", nil)) // warm the cache: online
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.authedReq("POST", "/api/games/windrose/stop", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("stop = %d, want 202", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req("GET", "/api/games/windrose/status", nil))
	if !strings.Contains(rec.Body.String(), `"stopping"`) {
		t.Fatalf("status right after stop = %s, want stopping", rec.Body.String())
	}
	h.App.Exclusivity.Wait()
}

func TestHealth_ReportsDockerReachability(t *testing.T) {
	up := newHarness(t, "#!/bin/sh\necho 29.0.0\n")
	rec := httptest.NewRecorder()
	up.mux().ServeHTTP(rec, up.req("GET", "/api/health", nil))
	if !strings.Contains(rec.Body.String(), `"docker":true`) {
		t.Fatalf("health with docker up = %s", rec.Body.String())
	}
	down := newHarness(t, "#!/bin/sh\necho 'secret path /var/run' >&2\nexit 1\n")
	rec = httptest.NewRecorder()
	down.mux().ServeHTTP(rec, down.req("GET", "/api/health", nil))
	if !strings.Contains(rec.Body.String(), `"docker":false`) || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("health with docker down = %s, want docker:false and no detail", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	up.mux().ServeHTTP(rec, httptest.NewRequest("GET", "/api/health", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated health = %d, want 401", rec.Code)
	}
}

func TestRoles_PlayersCannotTouchSettingsButCanControlGames(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	// Production points both at one UserStore; the harness has plain maps.
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RolePlayer}}

	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/settings"}, {"PUT", "/api/settings"},
	} {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq(tc.method, tc.path, []byte(`{}`)))
		if rec.Code != http.StatusForbidden {
			t.Errorf("player %s %s = %d, want 403", tc.method, tc.path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.authedReq("POST", "/api/games/windrose/start", nil))
	if rec.Code != http.StatusAccepted {
		t.Errorf("player start = %d, want 202", rec.Code)
	}
	h.App.Exclusivity.Wait()
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req("GET", "/", nil))
	if strings.Contains(rec.Body.String(), "settings-btn") {
		t.Error("dashboard shows the settings button to a player")
	}

	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RoleAdmin}}
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req("GET", "/", nil))
	if !strings.Contains(rec.Body.String(), "settings-btn") {
		t.Error("dashboard hides the settings button from an admin")
	}
}

func TestActivity_FeedAndSettingsAudit(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	store, err := history.Open(filepath.Join(t.TempDir(), "events.jsonl"), 0)
	if err != nil {
		t.Fatal(err)
	}
	h.App.History = store
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RoleAdmin}}
	h.App.Settings, _ = settings.New(settings.Values{IdleMinutes: 15, MaxActiveGames: 1, NightStartHour: 23, NightEndHour: 5}, "")

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.authedReq("PUT", "/api/settings", []byte(`{"idle_minutes":30}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT settings = %d: %s", rec.Code, rec.Body)
	}
	store.Record(history.KindJoin, "windrose", "ann", "")

	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req("GET", "/api/activity?limit=5", nil))
	var out struct {
		Events   []history.Event    `json:"events"`
		Playtime []history.Playtime `json:"playtime"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 2 || out.Events[0].Kind != history.KindJoin ||
		out.Events[1].Kind != history.KindSettings || out.Events[1].Detail != "idle_minutes 15→30" {
		t.Fatalf("events = %+v", out.Events)
	}
	if len(out.Playtime) != 1 || out.Playtime[0].Player != "ann" {
		t.Fatalf("playtime = %+v", out.Playtime)
	}
}

func TestHost_ReportsDisks(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	h.App.HostPaths = []string{t.TempDir()}
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req("GET", "/api/host", nil))
	var out struct {
		Disks []struct{ Total, Free uint64 } `json:"disks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Disks) != 1 || out.Disks[0].Total == 0 {
		t.Fatalf("host = %s (%v)", rec.Body, err)
	}
}

func TestBackup_AdminOnlyAndPreconditions(t *testing.T) {
	docker := fakeDockerClient(t, "#!/bin/sh\ncase \"$1\" in ps) case \"$*\" in *'name=^g$'*) echo g ;; esac ;; exec) exit 0 ;; esac\n")
	h := newHarnessFromDefs(t, docker, []games.GameDef{
		{ID: "g", DisplayName: "g", ContainerName: "g", Status: &games.DockerStatusChecker{Docker: docker},
			Backup: &games.BackupSpec{Exec: []string{"backup"}}},
		{ID: "plain", DisplayName: "plain", ContainerName: "plain", Status: &games.DockerStatusChecker{Docker: docker}},
	})
	h.App.Backups = &backup.Manager{Docker: docker}
	t.Cleanup(h.App.Backups.Wait)
	post := func(path string) int {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq("POST", path, nil))
		return rec.Code
	}

	if got := post("/api/games/g/backup"); got != http.StatusAccepted {
		t.Errorf("admin backup = %d, want 202", got)
	}
	h.App.Backups.Wait()
	if got := post("/api/games/plain/backup"); got != http.StatusNotFound {
		t.Errorf("backup of an unconfigured game = %d, want 404", got)
	}
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RolePlayer}}
	if got := post("/api/games/g/backup"); got != http.StatusForbidden {
		t.Errorf("player backup = %d, want 403", got)
	}
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req("GET", "/api/games/g/backups", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("player listing backups = %d, want 403", rec.Code)
	}
}

type fakeConsole struct{ ran []string }

func (f *fakeConsole) Actions() []games.ConsoleAction {
	return []games.ConsoleAction{{ID: "save", Label: "Save"}, {ID: "kick", Label: "Kick"}}
}
func (f *fakeConsole) Run(_ context.Context, action string, args map[string]string) (string, error) {
	f.ran = append(f.ran, action)
	if action == "kick" && args["userid"] == "" {
		return "", fmt.Errorf("%w: user id is required", games.ErrBadInput)
	}
	return "done " + action, nil
}
func (f *fakeConsole) Raw(_ context.Context, cmd string) (string, error) {
	f.ran = append(f.ran, "raw:"+cmd)
	return "echo " + cmd, nil
}

func TestConsole_ActionsRawToggleAndAudit(t *testing.T) {
	docker := fakeDockerClient(t, "#!/bin/sh\nexit 0\n")
	fc := &fakeConsole{}
	h := newHarnessFromDefs(t, docker, []games.GameDef{
		{ID: "g", DisplayName: "g", ContainerName: "g", Status: &games.DockerStatusChecker{Docker: docker}, Console: fc, RawConsole: fc},
		{ID: "plain", DisplayName: "plain", ContainerName: "plain", Status: &games.DockerStatusChecker{Docker: docker}},
	})
	hist, err := history.Open(filepath.Join(t.TempDir(), "e.jsonl"), 0)
	if err != nil {
		t.Fatal(err)
	}
	h.App.History = hist
	h.App.Settings, _ = settings.New(settings.Values{IdleMinutes: 15, MaxActiveGames: 1, NightStartHour: 23, NightEndHour: 5}, "")
	call := func(method, path, body string) (int, string) {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq(method, path, []byte(body)))
		return rec.Code, rec.Body.String()
	}

	if code, body := call("GET", "/api/games/g/console", ""); code != 200 || !strings.Contains(body, `"raw_enabled":false`) || !strings.Contains(body, `"raw_available":true`) {
		t.Fatalf("describe = %d %s", code, body)
	}
	if code, body := call("POST", "/api/games/g/console/action", `{"action":"save"}`); code != 200 || !strings.Contains(body, "done save") {
		t.Fatalf("action = %d %s", code, body)
	}
	if code, _ := call("POST", "/api/games/g/console/action", `{"action":"rm -rf"}`); code != 400 {
		t.Errorf("unknown action = %d, want 400", code)
	}
	if code, body := call("POST", "/api/games/g/console/action", `{"action":"kick","args":{}}`); code != 400 || !strings.Contains(body, "user id is required") {
		t.Errorf("bad input = %d %s", code, body)
	}
	if code, _ := call("POST", "/api/games/plain/console/action", `{"action":"save"}`); code != 404 {
		t.Errorf("game without console = %d, want 404", code)
	}

	// Raw console: refused until an admin switches it on.
	if code, _ := call("POST", "/api/games/g/console/raw", `{"command":"Info"}`); code != 403 {
		t.Fatalf("raw while off = %d, want 403", code)
	}
	for _, r := range fc.ran {
		if strings.HasPrefix(r, "raw:") {
			t.Fatal("raw command ran while the console was off")
		}
	}
	if code, _ := call("PUT", "/api/settings", `{"raw_console":true}`); code != 200 {
		t.Fatalf("enable raw console = %d", code)
	}
	if code, body := call("POST", "/api/games/g/console/raw", `{"command":"Info"}`); code != 200 || !strings.Contains(body, "echo Info") {
		t.Fatalf("raw while on = %d %s", code, body)
	}

	// Players can't use any of it, even with the raw console on.
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RolePlayer}}
	for _, p := range []string{"/api/games/g/console/action", "/api/games/g/console/raw"} {
		if code, _ := call("POST", p, `{"action":"save","command":"Info"}`); code != 403 {
			t.Errorf("player POST %s = %d, want 403", p, code)
		}
	}
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req("GET", "/api/games/g/console", nil))
	if rec.Code != 403 {
		t.Errorf("player describing console = %d, want 403", rec.Code)
	}

	var details []string
	for _, e := range hist.Recent(50, "g") {
		if e.Kind == history.KindConsole {
			details = append(details, e.Detail)
		}
	}
	if len(details) < 4 || !strings.Contains(strings.Join(details, "|"), "raw: Info") {
		t.Errorf("console audit trail = %v", details)
	}
}

type fakeManaged struct{ enabled []managed.Request }

func (f *fakeManaged) Catalogue() []managed.ModuleInfo {
	return []managed.ModuleInfo{{ID: "minecraft"}}
}
func (f *fakeManaged) List() []managed.Info { return nil }
func (f *fakeManaged) Preview(managed.Request) (*managed.Plan, error) {
	return &managed.Plan{Fits: true}, nil
}
func (f *fakeManaged) Enable(r managed.Request) error { f.enabled = append(f.enabled, r); return nil }
func (f *fakeManaged) Disable(string) error           { return nil }
func (f *fakeManaged) Update(managed.Request) error   { return nil }
func (f *fakeManaged) Refresh(string) error           { return nil }

func TestManagedAPI_AdminOnlyAndOptional(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RoleAdmin}}
	do := func(method, path string, body []byte) int {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq(method, path, body))
		return rec.Code
	}
	if c := do("GET", "/api/managed/modules", nil); c != http.StatusNotFound {
		t.Errorf("unconfigured: %d, want 404", c)
	}
	fm := &fakeManaged{}
	h.App.Managed = fm
	if c := do("GET", "/api/managed/modules", nil); c != http.StatusOK {
		t.Errorf("modules: %d", c)
	}
	if c := do("POST", "/api/managed/games", []byte(`{"id":"minecraft","module":"minecraft","secrets":{"rcon_password":"x"}}`)); c != http.StatusAccepted || len(fm.enabled) != 1 {
		t.Errorf("enable: %d %+v", c, fm.enabled)
	}
	if c := do("POST", "/api/managed/games", []byte(`{"id":"x","privileged":true}`)); c != http.StatusBadRequest {
		t.Errorf("unknown field: %d, want 400", c)
	}
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RolePlayer}}
	for _, p := range [][2]string{{"GET", "/api/managed/modules"}, {"GET", "/api/managed/games"}, {"POST", "/api/managed/preview"}, {"POST", "/api/managed/games"}, {"DELETE", "/api/managed/games/minecraft"}, {"PUT", "/api/managed/games/minecraft"}, {"POST", "/api/managed/games/minecraft/refresh"}} {
		if c := do(p[0], p[1], []byte(`{}`)); c != http.StatusForbidden {
			t.Errorf("player %s %s = %d, want 403", p[0], p[1], c)
		}
	}
}

func TestActivity_PlayersDoNotSeeAdminEvents(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	store, err := history.Open(filepath.Join(t.TempDir(), "events.jsonl"), 0)
	if err != nil {
		t.Fatal(err)
	}
	h.App.History = store
	store.Record(history.KindJoin, "windrose", "ann", "")
	store.Record(history.KindSettings, "", "root", "idle_minutes 15→30")
	store.Record(history.KindConsole, "windrose", "root", "say hi")
	store.Record(history.KindUsers, "", "root", "added x")
	store.Record(history.KindGames, "", "root", "edited")

	get := func(role auth.Role, limit string) []history.Event {
		h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: role}}
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.req("GET", "/api/activity?limit="+limit, nil))
		var out struct {
			Events []history.Event `json:"events"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Events
	}
	if ev := get(auth.RolePlayer, "1"); len(ev) != 1 || ev[0].Kind != history.KindJoin {
		t.Fatalf("player events = %+v, want just the join (limit filled past hidden kinds)", ev)
	}
	if ev := get(auth.RoleAdmin, "10"); len(ev) != 5 {
		t.Fatalf("admin events = %+v, want all 5", ev)
	}
}

func TestListGames_StartErrorDetailAdminOnly(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\ncase \"$1\" in ps) if [ \"$2\" = \"-a\" ]; then echo windrose; fi ;; start) echo 'boom: secret path' >&2; exit 1 ;; esac\n")
	if err := h.App.Exclusivity.RequestStart(context.Background(), "windrose"); err != nil {
		t.Fatal(err)
	}
	h.App.Exclusivity.Wait()
	get := func(role auth.Role) string {
		h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: role}}
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.req("GET", "/api/games", nil))
		return rec.Body.String()
	}
	if body := get(auth.RolePlayer); strings.Contains(body, "boom") || !strings.Contains(body, "start_error") {
		t.Fatalf("player body leaks or lacks error: %s", body)
	}
	if body := get(auth.RoleAdmin); !strings.Contains(body, "boom: secret path") {
		t.Fatalf("admin body lacks detail: %s", body)
	}
}

func TestHandleSwitch_CooldownIs429(t *testing.T) {
	script := "#!/bin/sh\ncase \"$1\" in ps) if [ \"$2\" = \"-a\" ]; then echo windrose; echo valheim; else echo valheim; fi ;; esac\n"
	docker := fakeDockerClient(t, script)
	mk := func(id string, cd time.Duration) games.GameDef {
		return games.GameDef{ID: id, DisplayName: id, ContainerName: id, RestartCooldown: cd,
			Status: &games.DockerStatusChecker{Docker: docker}, Players: games.UnknownPlayerCounter{}}
	}
	h := newHarnessFromDefs(t, docker, []games.GameDef{mk("windrose", time.Hour), mk("valheim", 0)})
	if err := h.App.Exclusivity.Stop(context.Background(), "windrose"); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(switchRequest{From: "valheim"})
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.authedReq(http.MethodPost, "/api/games/windrose/switch", body))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("switch = %d (Retry-After %q), want 429", rec.Code, rec.Header().Get("Retry-After"))
	}
}
