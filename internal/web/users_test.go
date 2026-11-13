package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/mfa"
	"github.com/fiddler110/crowsnest/internal/notify"
	"github.com/fiddler110/crowsnest/internal/settings"
	"github.com/fiddler110/crowsnest/internal/vault"
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

	want(do("PUT", "/api/users/bob", `{"role":"admin","password":"newpassw0rd","confirm_password":"whatever1"}`), http.StatusOK)
	if r, _ := store.Lookup("bob"); r.EffectiveRole() != auth.RoleAdmin || !auth.VerifyPassword(r.Hash, "newpassw0rd") || r.ValidAfter.IsZero() {
		t.Errorf("bob = %+v", r)
	}

	// Self-protection.
	want(do("PUT", "/api/users/tester", `{"role":"player","confirm_password":"whatever1"}`), http.StatusBadRequest)
	want(do("DELETE", "/api/users/tester", ""), http.StatusBadRequest)
	want(do("PUT", "/api/users/tester", `{"revoke_sessions":true}`), http.StatusBadRequest)
	want(do("PUT", "/api/users/ghost", `{"role":"admin"}`), http.StatusNotFound)

	// Last-admin guard: demote bob back, then tester is the only admin.
	want(do("PUT", "/api/users/bob", `{"role":"player","confirm_password":"whatever1"}`), http.StatusOK)
	want(do("DELETE", "/api/users/bob", `{"confirm_password":"whatever1"}`), http.StatusOK)
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
	if h.App.OIDC == nil {
		ostore, _ := auth.NewOIDCStore(filepath.Join(t.TempDir(), "oidc.json"), nil)
		h.App.OIDC = &auth.OIDCLogin{Service: h.App.Auth, Store: ostore}
	}
	h.App.OIDC.Google = h.App.Google

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
	code(do("PUT", "/api/users/gina", `{"google_email":"","confirm_password":"whatever1"}`), http.StatusBadRequest)
	code(do("PUT", "/api/users/gina", `{"password":"longenough1","google_email":"","confirm_password":"whatever1"}`), http.StatusBadRequest) // email cleared before hash exists
	code(do("PUT", "/api/users/gina", `{"google_email":"gina2@example.com","confirm_password":"whatever1"}`), http.StatusOK)
	if _, ok := h.App.Google.Lookup("gina@example.com"); ok {
		t.Error("old email still allowed")
	}
	code(do("DELETE", "/api/users/gina", `{"confirm_password":"whatever1"}`), http.StatusOK)
	if h.App.Google.Allows("gina") {
		t.Error("deleted user still allowed")
	}
}

func TestGameAllowlistHidesGames(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n", "palworld", "valheim")
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RolePlayer, Games: []string{"palworld"}}}
	do := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq(method, path, []byte(body)))
		return rec
	}

	var list []gameSummary
	rec := do("GET", "/api/games", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0].ID != "palworld" {
		t.Fatalf("games = %s (%v)", rec.Body.String(), err)
	}
	for _, p := range []string{"/api/games/valheim/status", "/api/games/valheim/players", "/api/games/valheim/info"} {
		if rec := do("GET", p, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, rec.Code)
		}
	}
	if rec := do("POST", "/api/games/valheim/start", ""); rec.Code != http.StatusNotFound {
		t.Errorf("start hidden game = %d, want 404", rec.Code)
	}
	if rec := do("POST", "/api/games/palworld/switch", `{"from":"valheim"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("switch from hidden game = %d, want 400", rec.Code)
	}
	if rec := do("GET", "/api/games/palworld/status", ""); rec.Code != http.StatusOK {
		t.Errorf("allowed game status = %d", rec.Code)
	}

	// Admins ignore the list.
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RoleAdmin, Games: []string{"palworld"}}}
	rec = do("GET", "/api/games", "")
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 2 {
		t.Errorf("admin sees %d games, want 2", len(list))
	}
}

func TestUsersAPIGames(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n", "palworld", "valheim")
	path := filepath.Join(t.TempDir(), "users")
	hash, _ := auth.HashPassword("whatever1")
	if err := auth.SetUserHash(path, "tester", hash); err != nil {
		t.Fatal(err)
	}
	store, _ := auth.NewUserStore(path)
	h.App.Auth.Store = store
	h.App.Auth.Sessions.Store = store
	do := func(method, p, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq(method, p, []byte(body)))
		return rec
	}
	if rec := do("POST", "/api/users", `{"username":"bob","password":"hunter22x","games":["palworld"]}`); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := do("PUT", "/api/users/bob", `{"games":["nope"]}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown game = %d, want 400", rec.Code)
	}
	if rec := do("PUT", "/api/users/bob", `{"games":["valheim","palworld"]}`); rec.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", rec.Code, rec.Body.String())
	}
	rec := do("GET", "/api/users", "")
	var out struct{ Users []userView }
	json.Unmarshal(rec.Body.Bytes(), &out)
	if got := out.Users[0].Games; len(got) != 2 || got[0] != "palworld" {
		t.Fatalf("games = %v", got)
	}
	if rec := do("PUT", "/api/users/bob", `{"games":[]}`); rec.Code != http.StatusOK {
		t.Fatalf("clear = %d", rec.Code)
	}
	if rec := do("PUT", "/api/users/bob", `{"games":[]}`); rec.Code != http.StatusBadRequest {
		t.Errorf("no-op update = %d, want 400", rec.Code)
	}
}

func TestGoogleSettingsAPI(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	hash, _ := auth.HashPassword("whatever1")
	if err := auth.SetUserHash(users, "tester", hash); err != nil {
		t.Fatal(err)
	}
	store, _ := auth.NewUserStore(users)
	h.App.Auth.Store, h.App.Auth.Sessions.Store = store, store
	h.App.Google = &auth.GoogleLogin{Store: store}
	if h.App.OIDC == nil {
		ostore, _ := auth.NewOIDCStore(filepath.Join(t.TempDir(), "oidc.json"), nil)
		h.App.OIDC = &auth.OIDCLogin{Service: h.App.Auth, Store: ostore}
	}
	h.App.OIDC.Google = h.App.Google
	vlt, err := vault.New("", filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	conf, err := auth.NewGoogleConfStore(filepath.Join(dir, "auth.json"), vlt, auth.GoogleSettings{})
	if err != nil {
		t.Fatal(err)
	}
	h.App.GoogleConf = conf
	conf.Apply(h.App.Google)

	do := func(method, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq(method, "/api/auth/google", []byte(body)))
		return rec
	}
	if h.App.Google.Active() {
		t.Fatal("Google is active before anything is configured")
	}
	// start route is 404 while off
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, auth.GoogleStartPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("start while off = %d, want 404", rec.Code)
	}

	good := `{"enabled":true,"client_id":"cid","client_secret":"shh-secret","redirect_url":"https://c.example/auth/google/callback"`
	if rec := do("PUT", good+`,"password":"wrong"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong password = %d", rec.Code)
	}
	if rec := do("PUT", `{"enabled":true,"client_id":"cid","redirect_url":"https://c.example/auth/google/callback","password":"whatever1"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("no secret = %d, want 400", rec.Code)
	}
	rec = do("PUT", good+`,"password":"whatever1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("save = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "shh-secret") {
		t.Fatal("response leaks the client secret")
	}
	if !h.App.Google.Active() {
		t.Fatal("not active after saving")
	}
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, auth.GoogleStartPath, nil))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "client_id=cid") {
		t.Fatalf("start after save = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	// Keeping the secret: omit it.
	if rec := do("PUT", `{"enabled":true,"client_id":"cid2","redirect_url":"https://c.example/auth/google/callback","password":"whatever1"}`); rec.Code != http.StatusOK {
		t.Fatalf("update without secret = %d: %s", rec.Code, rec.Body.String())
	}
	if v, _ := conf.Effective(); v.ClientSecret != "shh-secret" || v.ClientID != "cid2" {
		t.Fatalf("effective = %+v", v)
	}
	// Turning it off is allowed while passwords work, and the routes go dark.
	if rec := do("PUT", `{"enabled":false,"client_id":"cid2","redirect_url":"https://c.example/auth/google/callback","password":"whatever1"}`); rec.Code != http.StatusOK {
		t.Fatalf("disable = %d", rec.Code)
	}
	if h.App.Google.Active() {
		t.Fatal("still active after disabling")
	}
	// Not when password sign-in is off: that would lock everyone out.
	h.App.Auth.DisablePasswordLogin = true
	if rec := do("PUT", `{"enabled":false,"client_id":"cid2","redirect_url":"https://c.example/auth/google/callback","password":"whatever1"}`); rec.Code != http.StatusConflict {
		t.Errorf("disable with passwords off = %d, want 409", rec.Code)
	}
	h.App.Auth.DisablePasswordLogin = false
	if rec := do("DELETE", `{"password":"whatever1"}`); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}
	if _, src := conf.Effective(); src != auth.GoogleSourceNone {
		t.Errorf("source after delete = %s", src)
	}
}

func TestPasswordLoginSwitch(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	hash, _ := auth.HashPassword("whatever1")
	auth.SetUserHash(users, "tester", hash) // an admin with a password and no Google link
	auth.CreateUser(users, "linked", hash, "l@x.org", auth.RoleAdmin)
	auth.CreateUser(users, "pwonly", hash, "", auth.RolePlayer)
	store, _ := auth.NewUserStore(users)
	h.App.Auth.Store, h.App.Auth.Sessions.Store = store, store
	h.App.Google = &auth.GoogleLogin{Store: store}
	if h.App.OIDC == nil {
		ostore, _ := auth.NewOIDCStore(filepath.Join(t.TempDir(), "oidc.json"), nil)
		h.App.OIDC = &auth.OIDCLogin{Service: h.App.Auth, Store: ostore}
	}
	h.App.OIDC.Google = h.App.Google
	prefs, err := auth.NewPrefsStore(filepath.Join(dir, "prefs.json"))
	if err != nil {
		t.Fatal(err)
	}
	h.App.AuthPrefs = prefs
	put := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq("PUT", "/api/auth/password-login", []byte(body)))
		return rec
	}

	// Off: warns first, naming who is locked out, including the caller.
	rec := put(`{"enabled":false,"password":"whatever1"}`)
	var warn struct {
		NeedsConfirm bool     `json:"needs_confirm"`
		LockedOut    []string `json:"locked_out"`
		You          bool     `json:"you_locked_out"`
	}
	json.Unmarshal(rec.Body.Bytes(), &warn)
	if rec.Code != http.StatusConflict || !warn.NeedsConfirm || !warn.You || len(warn.LockedOut) != 2 {
		t.Fatalf("first attempt = %d %s", rec.Code, rec.Body.String())
	}
	if !h.App.Auth.PasswordLoginDisabled() == false {
		t.Fatal("changed before confirmation")
	}
	if rec := put(`{"enabled":false,"password":"nope","confirm":true}`); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong password = %d", rec.Code)
	}
	if rec := put(`{"enabled":false,"password":"whatever1","confirm":true}`); rec.Code != http.StatusOK {
		t.Fatalf("confirmed = %d %s", rec.Code, rec.Body.String())
	}
	if !h.App.Auth.PasswordLoginDisabled() || prefs.PasswordLogin() == nil {
		t.Fatal("not applied or not saved")
	}
	// Back on needs no confirmation.
	if rec := put(`{"enabled":true,"password":"whatever1"}`); rec.Code != http.StatusOK || h.App.Auth.PasswordLoginDisabled() {
		t.Fatalf("on again = %d", rec.Code)
	}
	// With no admin reachable by Google it is refused outright, even confirmed.
	auth.SetGoogleEmail(users, "linked", "")
	store.Reload()
	rec = put(`{"enabled":false,"password":"whatever1","confirm":true}`)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"refused":true`) || h.App.Auth.PasswordLoginDisabled() {
		t.Fatalf("no-admin case = %d %s", rec.Code, rec.Body.String())
	}
}

func TestTOTPEnrolmentAPI(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	hash, _ := auth.HashPassword("whatever1")
	auth.SetUserHash(users, "tester", hash)
	auth.CreateUser(users, "bob", hash, "", auth.RolePlayer)
	store, _ := auth.NewUserStore(users)
	h.App.Auth.Store, h.App.Auth.Sessions.Store = store, store
	vlt, _ := vault.New("", filepath.Join(dir, "k"))
	ms, err := mfa.NewStore(filepath.Join(dir, "mfa.json"), vlt)
	if err != nil {
		t.Fatal(err)
	}
	h.App.MFA = ms
	call := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq(method, path, []byte(body)))
		return rec
	}

	if rec := call("POST", "/api/account/totp/begin", `{"password":"wrong"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("begin with a wrong password = %d", rec.Code)
	}
	rec := call("POST", "/api/account/totp/begin", `{"password":"whatever1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin = %d %s", rec.Code, rec.Body.String())
	}
	var begun struct{ Secret, URI string }
	json.Unmarshal(rec.Body.Bytes(), &begun)
	if !strings.HasPrefix(begun.URI, "otpauth://totp/CrowsNest:tester?") || begun.Secret == "" {
		t.Fatalf("begin body = %s", rec.Body.String())
	}
	if rec := call("GET", "/api/account/totp/qr", ""); rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("qr = %d %s %s", rec.Code, rec.Header().Get("Content-Type"), rec.Header().Get("Cache-Control"))
	}
	if rec := call("POST", "/api/account/totp/confirm", `{"code":"000000"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("confirm with a wrong code = %d", rec.Code)
	}
	code, _ := mfa.Code(begun.Secret, time.Now())
	rec = call("POST", "/api/account/totp/confirm", `{"code":"`+code+`"}`)
	var done struct {
		Codes []string `json:"recovery_codes"`
	}
	json.Unmarshal(rec.Body.Bytes(), &done)
	if rec.Code != 200 || len(done.Codes) != 10 || !ms.Enabled("tester") {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	// Once enrolled the QR (which carries the secret) is gone.
	if rec := call("GET", "/api/account/totp/qr", ""); rec.Code != http.StatusNotFound {
		t.Errorf("qr after enrolment = %d, want 404", rec.Code)
	}
	// Turning it off needs the password and a code: a recovery code will do.
	if rec := call("POST", "/api/account/totp/disable", `{"password":"whatever1","code":"000000"}`); rec.Code != http.StatusForbidden || !ms.Enabled("tester") {
		t.Fatalf("disable with a wrong code = %d", rec.Code)
	}
	if rec := call("POST", "/api/account/totp/disable", `{"password":"whatever1","code":"`+done.Codes[0]+`"}`); rec.Code != 200 || ms.Enabled("tester") {
		t.Fatalf("disable with a recovery code = %d %s", rec.Code, rec.Body.String())
	}

	// An admin can reset another user's app.
	secret, _ := ms.Begin("bob")
	c, _ := mfa.Code(secret, time.Now())
	ms.Confirm("bob", c)
	if rec := call("PUT", "/api/users/bob", `{"reset_mfa":true,"confirm_password":"whatever1"}`); rec.Code != 200 || ms.Enabled("bob") {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body.String())
	}
	if rec := call("PUT", "/api/users/bob", `{"reset_mfa":true,"confirm_password":"whatever1"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("reset with nothing to reset = %d, want 400", rec.Code)
	}
}

func TestOIDCProvidersAPI(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		json.NewEncoder(w).Encode(map[string]any{"issuer": base, "authorization_endpoint": base + "/auth", "token_endpoint": base + "/token"})
	}))
	defer idp.Close()

	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	hash, _ := auth.HashPassword("whatever1")
	auth.SetUserHash(users, "tester", hash)
	store, _ := auth.NewUserStore(users)
	h.App.Auth.Store, h.App.Auth.Sessions.Store = store, store
	vlt, _ := vault.New("", filepath.Join(dir, "k"))
	ostore, err := auth.NewOIDCStore(filepath.Join(dir, "oidc.json"), vlt)
	if err != nil {
		t.Fatal(err)
	}
	h.App.OIDC = &auth.OIDCLogin{Store: ostore, Users: store, Service: h.App.Auth}
	call := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq(method, path, []byte(body)))
		return rec
	}
	body := func(secret string, enabled bool, pw string) string {
		return `{"name":"Authentik","issuer":"` + idp.URL + `","client_id":"cid","client_secret":"` + secret + `","redirect_url":"http://localhost/auth/oidc/ak/callback","enabled":` + map[bool]string{true: "true", false: "false"}[enabled] + `,"password":"` + pw + `"}`
	}
	if rec := call("PUT", "/api/auth/oidc/ak", body("top-secret-value", true, "wrong")); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong password = %d", rec.Code)
	}
	if rec := call("PUT", "/api/auth/oidc/AK!", body("top-secret-value", true, "whatever1")); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad id = %d", rec.Code)
	}
	rec := call("PUT", "/api/auth/oidc/ak", body("top-secret-value", true, "whatever1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("save = %d %s", rec.Code, rec.Body.String())
	}
	for _, r := range []*httptest.ResponseRecorder{rec, call("GET", "/api/auth/oidc", "")} {
		if strings.Contains(r.Body.String(), "top-secret-value") {
			t.Fatal("a response leaks the client secret")
		}
	}
	if p, _ := ostore.Get("ak"); p.AuthURL == "" || !p.Enabled {
		t.Fatalf("provider = %+v", p)
	}
	// The login page offers it, and the start route redirects to its endpoint.
	login := httptest.NewRecorder()
	h.mux().ServeHTTP(login, httptest.NewRequest("GET", "/login", nil))
	if !strings.Contains(login.Body.String(), "Sign in with Authentik") {
		t.Error("login page has no button for the provider")
	}
	start := httptest.NewRecorder()
	h.mux().ServeHTTP(start, httptest.NewRequest("GET", "/auth/oidc/ak/start", nil))
	if start.Code != http.StatusFound || !strings.HasPrefix(start.Header().Get("Location"), idp.URL+"/auth?") {
		t.Fatalf("start = %d %s", start.Code, start.Header().Get("Location"))
	}
	// Updating without the secret keeps it; moving the issuer without one is refused.
	if rec := call("PUT", "/api/auth/oidc/ak", `{"name":"Authentik","issuer":"`+idp.URL+`","client_id":"cid","redirect_url":"http://localhost/auth/oidc/ak/callback","enabled":true,"password":"whatever1"}`); rec.Code != http.StatusOK {
		t.Fatalf("update = %d %s", rec.Code, rec.Body.String())
	}
	if p, _ := ostore.Get("ak"); p.ClientSecret != "top-secret-value" {
		t.Fatal("the secret was lost on update")
	}
	// Removing it works with the password.
	if rec := call("DELETE", "/api/auth/oidc/ak", `{"password":"whatever1"}`); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body.String())
	}
	if len(ostore.List()) != 0 {
		t.Fatal("provider still listed")
	}
}

func TestUsersAPI_StepUp(t *testing.T) {
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
	do := func(method, p, body string) int {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq(method, p, []byte(body)))
		return rec.Code
	}
	ok, bad := `"confirm_password":"whatever1"`, `"confirm_password":"nope"`
	// Creating a player needs no step-up; an admin does.
	if got := do("POST", "/api/users", `{"username":"bob","password":"hunter22x","role":"player"}`); got != http.StatusCreated {
		t.Fatalf("create player = %d", got)
	}
	for _, body := range []string{
		`{"username":"eve","password":"hunter22x","role":"admin"}`,
		`{"username":"eve","password":"hunter22x","role":"admin",` + bad + `}`,
	} {
		if got := do("POST", "/api/users", body); got != http.StatusForbidden {
			t.Errorf("create admin %s = %d, want 403", body, got)
		}
	}
	if _, found := store.Lookup("eve"); found {
		t.Fatal("admin was created without the password")
	}
	if got := do("POST", "/api/users", `{"username":"eve","password":"hunter22x","role":"admin",`+ok+`}`); got != http.StatusCreated {
		t.Errorf("create admin with the password = %d", got)
	}
	// Each of these changes who can sign in as bob, so each is refused without it.
	for _, body := range []string{
		`{"role":"admin"}`, `{"password":"newpassw0rd"}`, `{"reset_mfa":true}`, `{"role":"admin",` + bad + `}`,
	} {
		if got := do("PUT", "/api/users/bob", body); got != http.StatusForbidden {
			t.Errorf("PUT %s = %d, want 403", body, got)
		}
	}
	if r, _ := store.Lookup("bob"); r.EffectiveRole() != auth.RolePlayer || !auth.VerifyPassword(r.Hash, "hunter22x") {
		t.Errorf("bob changed without the password: %+v", r)
	}
	// An admin changing their own password is asked for the current one too.
	if got := do("PUT", "/api/users/tester", `{"password":"another-pass1"}`); got != http.StatusForbidden {
		t.Errorf("own password change without the current one = %d, want 403", got)
	}
	if got := do("PUT", "/api/users/tester", `{"password":"another-pass1",`+ok+`}`); got != http.StatusOK {
		t.Errorf("own password change with the current one = %d, want 200", got)
	}
	// Games and sign-outs stay a single click.
	if got := do("PUT", "/api/users/bob", `{"revoke_sessions":true}`); got != http.StatusOK {
		t.Errorf("revoke sessions = %d, want 200", got)
	}
	if got := do("DELETE", "/api/users/bob", ``); got != http.StatusBadRequest && got != http.StatusForbidden {
		t.Errorf("delete without the password = %d, want refusal", got)
	}
	if _, found := store.Lookup("bob"); !found {
		t.Fatal("bob was deleted without the password")
	}
}

func TestChangeOwnPassword(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	users := filepath.Join(t.TempDir(), "users")
	hash, _ := auth.HashPassword("whatever1")
	auth.SetUserHash(users, "tester", hash)
	store, _ := auth.NewUserStore(users)
	h.App.Auth.Store, h.App.Auth.Sessions.Store = store, store
	call := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq("POST", "/api/account/password", []byte(body)))
		return rec
	}
	for name, c := range map[string]struct {
		body string
		want int
	}{
		"wrong current": {`{"current":"nope","new":"another-pass"}`, http.StatusForbidden},
		"too short":     {`{"current":"whatever1","new":"short"}`, http.StatusBadRequest},
		"same":          {`{"current":"whatever1","new":"whatever1"}`, http.StatusBadRequest},
	} {
		if rec := call(c.body); rec.Code != c.want {
			t.Errorf("%s = %d %s, want %d", name, rec.Code, rec.Body.String(), c.want)
		}
	}
	if rec := call(`{"current":"whatever1","new":"another-pass"}`); rec.Code != 200 {
		t.Fatalf("change = %d %s", rec.Code, rec.Body.String())
	}
	store.Reload()
	rec, _ := store.Lookup("tester")
	if !auth.VerifyPassword(rec.Hash, "another-pass") || auth.VerifyPassword(rec.Hash, "whatever1") {
		t.Error("the stored hash was not replaced")
	}
}

func TestMentionsAPI(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	h.App.Mentions, _ = notify.OpenMentions("")
	h.App.DiscordOn = true
	put := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq("PUT", "/api/account/mentions", []byte(body)))
		return rec
	}
	if rec := put(`{"discord_id":"abc","games":["windrose"]}`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad id = %d", rec.Code)
	}
	rec := put(`{"discord_id":"12345678901234567","games":["windrose","nosuch"]}`)
	if rec.Code != 200 {
		t.Fatalf("save = %d %s", rec.Code, rec.Body.String())
	}
	var v mentionView
	json.Unmarshal(rec.Body.Bytes(), &v)
	if !v.Available || v.DiscordID == "" || len(v.Games) != 1 || !v.Games[0].Checked {
		t.Fatalf("view = %+v", v)
	}
	if ids := h.App.Mentions.IDsFor("nosuch"); len(ids) != 0 {
		t.Errorf("an unknown game was kept: %v", ids)
	}
}

func TestMFAGate(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	hash, _ := auth.HashPassword("whatever1")
	auth.SetUserHash(users, "tester", hash)
	store, _ := auth.NewUserStore(users)
	h.App.Auth.Store, h.App.Auth.Sessions.Store = store, store
	vlt, _ := vault.New("", filepath.Join(dir, "k"))
	h.App.MFA, _ = mfa.NewStore(filepath.Join(dir, "mfa.json"), vlt)
	h.App.Settings, _ = settings.New(settings.Values{IdleMinutes: 15, NightStartHour: 23, NightEndHour: 5, MaxActiveGames: 1}, "")
	gate := h.App.MFAGate(h.mux())
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, h.authedReq("GET", path, nil))
		return rec
	}
	if rec := get("/api/games"); rec.Code != 200 {
		t.Fatalf("gate off: games = %d", rec.Code)
	}
	h.App.Settings.Modify(func(v *settings.Values) error { v.RequireAdminMFA = true; return nil })
	if rec := get("/api/games"); rec.Code != http.StatusForbidden {
		t.Errorf("gate on, no app: api = %d, want 403", rec.Code)
	}
	if rec := get("/settings"); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account#totp" {
		t.Errorf("gate on: page = %d %s, want a redirect to the account page", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get("/api/account/security"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"mfa_required":true`) {
		t.Errorf("account security = %d %s", rec.Code, rec.Body.String())
	}
	if rec := get("/account"); rec.Code != 200 {
		t.Errorf("account page = %d, want it reachable", rec.Code)
	}
}
