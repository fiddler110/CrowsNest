package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/auth"
)

func TestUsersAPI(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	path := filepath.Join(t.TempDir(), "users")
	hash, _ := auth.HashPassword("whatever1")
	if err := auth.SetUserHash(path, "tester", hash); err != nil {
		t.Fatal(err)
	}
	store, err := auth.NewUserStore(path)
	if err != nil {
		t.Fatal(err)
	}
	h.App.Auth.Store = store
	h.App.Auth.Sessions.Store = store

	do := func(method, p, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		var b []byte
		if body != "" {
			b = []byte(body)
		}
		h.mux().ServeHTTP(rec, h.authedReq(method, p, b))
		return rec
	}
	want := func(rec *httptest.ResponseRecorder, code int) {
		t.Helper()
		if rec.Code != code {
			t.Fatalf("status = %d, want %d: %s", rec.Code, code, rec.Body.String())
		}
	}

	want(do("POST", "/api/users", `{"username":"Bob","password":"hunter22x","role":"player"}`), http.StatusCreated)
	want(do("POST", "/api/users", `{"username":"bob","password":"hunter22x"}`), http.StatusConflict)
	want(do("POST", "/api/users", `{"username":"bad name","password":"hunter22x"}`), http.StatusBadRequest)
	want(do("POST", "/api/users", `{"username":"short","password":"abc"}`), http.StatusBadRequest)

	rec := do("GET", "/api/users", "")
	want(rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), "$2a$") {
		t.Error("user list leaks password hashes")
	}
	var out struct{ Users []userView }
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Users) != 2 || out.Users[0].Username != "bob" || out.Users[0].Role != auth.RolePlayer || !out.Users[1].Self {
		t.Fatalf("users = %+v", out.Users)
	}

	want(do("PUT", "/api/users/bob", `{"role":"admin","password":"newpassw0rd"}`), http.StatusOK)
	if r, _ := store.Lookup("bob"); r.EffectiveRole() != auth.RoleAdmin || !auth.VerifyPassword(r.Hash, "newpassw0rd") || r.ValidAfter.IsZero() {
		t.Errorf("bob = %+v", r)
	}

	// Self-protection.
	want(do("PUT", "/api/users/tester", `{"role":"player"}`), http.StatusBadRequest)
	want(do("DELETE", "/api/users/tester", ""), http.StatusBadRequest)
	want(do("PUT", "/api/users/tester", `{"revoke_sessions":true}`), http.StatusBadRequest)
	want(do("PUT", "/api/users/ghost", `{"role":"admin"}`), http.StatusNotFound)

	// Last-admin guard: demote bob back, then tester is the only admin.
	want(do("PUT", "/api/users/bob", `{"role":"player"}`), http.StatusOK)
	want(do("DELETE", "/api/users/bob", ""), http.StatusOK)
	if _, ok := store.Lookup("bob"); ok {
		t.Error("bob still present after delete")
	}
}

func TestUsersAPI_PlayersForbidden(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RolePlayer}}
	for _, tc := range []struct{ m, p string }{{"GET", "/api/users"}, {"POST", "/api/users"}, {"PUT", "/api/users/x"}, {"DELETE", "/api/users/x"}} {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq(tc.m, tc.p, []byte(`{}`)))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403", tc.m, tc.p, rec.Code)
		}
	}
}

func TestUsersAPI_GoogleOnly(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	path := filepath.Join(t.TempDir(), "users")
	hash, _ := auth.HashPassword("whatever1")
	auth.SetUserHash(path, "tester", hash)
	store, _ := auth.NewUserStore(path)
	h.App.Auth.Store = store
	h.App.Auth.Sessions.Store = store
	h.App.Google = &auth.GoogleLogin{Users: auth.GoogleUsers{"env@example.com": "envuser"}, Store: store}

	do := func(method, p, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq(method, p, []byte(body)))
		return rec
	}
	code := func(rec *httptest.ResponseRecorder, want int) {
		t.Helper()
		if rec.Code != want {
			t.Fatalf("status = %d, want %d: %s", rec.Code, want, rec.Body.String())
		}
	}

	code(do("POST", "/api/users", `{"username":"gina","google_email":"Gina@Example.com","role":"player"}`), http.StatusCreated)
	if name, ok := h.App.Google.Lookup("gina@example.com"); !ok || name != "gina" {
		t.Errorf("Lookup = %q, %v", name, ok)
	}
	if !h.App.Google.Allows("gina") {
		t.Error("Allows(gina) = false")
	}
	if rec, _ := store.Lookup("gina"); rec.Hash != "" {
		t.Error("google-only user got a password hash")
	}
	// Neither password nor email, bad email, duplicates (file and env).
	code(do("POST", "/api/users", `{"username":"nobody"}`), http.StatusBadRequest)
	code(do("POST", "/api/users", `{"username":"x1","google_email":"nope"}`), http.StatusBadRequest)
	code(do("POST", "/api/users", `{"username":"x2","google_email":"gina@example.com"}`), http.StatusBadRequest)
	code(do("POST", "/api/users", `{"username":"x3","google_email":"env@example.com"}`), http.StatusBadRequest)

	// A google-only user can't drop the link without a password.
	code(do("PUT", "/api/users/gina", `{"google_email":""}`), http.StatusBadRequest)
	code(do("PUT", "/api/users/gina", `{"password":"longenough1","google_email":""}`), http.StatusBadRequest) // email cleared before hash exists
	code(do("PUT", "/api/users/gina", `{"google_email":"gina2@example.com"}`), http.StatusOK)
	if _, ok := h.App.Google.Lookup("gina@example.com"); ok {
		t.Error("old email still allowed")
	}
	code(do("DELETE", "/api/users/gina", ""), http.StatusOK)
	if h.App.Google.Allows("gina") {
		t.Error("deleted user still allowed")
	}
}
