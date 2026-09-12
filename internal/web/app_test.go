package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/exclusivity"
	"github.com/fiddler110/crowsnest/internal/games"
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
	app := &App{
		Registry:    registry,
		Docker:      docker,
		Exclusivity: exclusivity.NewManager(registry, docker),
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
	h.App.Auth.Users["tester"] = hash

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
