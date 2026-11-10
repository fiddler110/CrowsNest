package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/auth"
)

// setupHarness is a harness whose users file is empty and which offers setup.
func setupHarness(t *testing.T) (*testHarness, *auth.Setup, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "users.env")
	store, err := auth.NewUserStore(path)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, psOnlyRunning, "palworld")
	h.App.Auth.Store = store
	setup := &auth.Setup{Store: store, CodeFile: filepath.Join(dir, "setup-token")}
	h.App.Setup = setup
	return h, setup, path
}

func postSetup(h *testHarness, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.mux().ServeHTTP(rec, req)
	return rec
}

func TestSetup_LoginRedirectsUntilAUserExists(t *testing.T) {
	h, setup, _ := setupHarness(t)
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/setup" {
		t.Fatalf("GET /login with no users = %d %q, want a redirect to /setup", rec.Code, rec.Header().Get("Location"))
	}
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/setup", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="setup-form"`) {
		t.Fatalf("GET /setup = %d", rec.Code)
	}
	if _, err := os.Stat(setup.CodeFile); err != nil {
		t.Fatalf("visiting /setup should leave a setup code on disk: %v", err)
	}
}

func TestSetup_CreatesTheFirstAdminOnce(t *testing.T) {
	h, setup, path := setupHarness(t)
	code, _, err := setup.Code()
	if err != nil {
		t.Fatal(err)
	}

	if rec := postSetup(h, `{"code":"wrong","username":"owner","password":"correct horse"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong code = %d, want 403", rec.Code)
	}
	if rec := postSetup(h, `{"code":"`+code+`","username":"owner","password":"short"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("short password = %d, want 400", rec.Code)
	}
	if users, _ := auth.LoadUsers(path); len(users) != 0 {
		t.Fatal("a refused setup must not create a user")
	}

	if rec := postSetup(h, `{"code":"`+code+`","username":"Owner","password":"correct horse"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("setup = %d %s, want 204", rec.Code, rec.Body.String())
	}
	rec, ok := h.App.Auth.Store.Lookup("owner")
	if !ok || rec.EffectiveRole() != auth.RoleAdmin || rec.Hash == "" {
		t.Fatalf("owner = %+v, %v; want an admin with a password", rec, ok)
	}
	if _, err := os.Stat(setup.CodeFile); !os.IsNotExist(err) {
		t.Fatalf("the setup code should be deleted once used: %v", err)
	}

	// Closed for good: even the right code no longer works.
	if rec := postSetup(h, `{"code":"`+code+`","username":"intruder","password":"correct horse"}`); rec.Code != http.StatusConflict {
		t.Fatalf("second setup = %d, want 409", rec.Code)
	}
	rec2 := httptest.NewRecorder()
	h.mux().ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/setup", nil))
	if rec2.Code != http.StatusSeeOther || rec2.Header().Get("Location") != "/login" {
		t.Fatalf("GET /setup after setup = %d, want a redirect to /login", rec2.Code)
	}
	// And the new admin can sign in.
	login := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"owner","password":"correct horse"}`))
	h.mux().ServeHTTP(login, req)
	if login.Code != http.StatusOK {
		t.Fatalf("login as the new admin = %d", login.Code)
	}
}

func TestSetup_CodeSurvivesARestart(t *testing.T) {
	_, setup, _ := setupHarness(t)
	first, created, _ := setup.Code()
	if !created {
		t.Fatal("the first call should create the code")
	}
	again := &auth.Setup{Store: setup.Store, CodeFile: setup.CodeFile}
	if second, created, _ := again.Code(); second != first || created {
		t.Fatalf("code after a restart = %q (created %v), want the saved %q", second, created, first)
	}
}

func TestSetup_OffWhenNotWired(t *testing.T) {
	h := newHarness(t, psOnlyRunning, "palworld")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/login without Setup = %d, want the sign-in page", rec.Code)
	}
	if rec := postSetup(h, `{}`); rec.Code != http.StatusConflict {
		t.Fatalf("POST /setup without Setup = %d, want 409", rec.Code)
	}
}
