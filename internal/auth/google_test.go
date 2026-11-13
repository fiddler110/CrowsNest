package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/fiddler110/crowsnest/internal/vault"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testClientID = "client-123.apps.googleusercontent.com"

// fakeGoogle is a stand-in token endpoint. It records the form it was sent and
// answers with an ID token built from claims (tweakable per test).
type fakeGoogle struct {
	mu       sync.Mutex
	form     url.Values
	status   int
	claims   map[string]any
	noIDTok  bool
	requests int
}

func (f *fakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	_ = r.ParseForm()
	f.form = r.PostForm
	if f.status != 0 && f.status != http.StatusOK {
		w.WriteHeader(f.status)
		return
	}
	resp := map[string]any{"access_token": "at", "token_type": "Bearer"}
	if !f.noIDTok {
		resp["id_token"] = makeJWT(f.claims)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func makeJWT(claims map[string]any) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	p, _ := json.Marshal(claims)
	return h + "." + base64.RawURLEncoding.EncodeToString(p) + ".c2ln"
}

type googleHarness struct {
	g    *GoogleLogin
	o    *OIDCLogin
	fake *fakeGoogle
	now  time.Time
}

func newGoogleHarness(t *testing.T) *googleHarness {
	t.Helper()
	fake := &fakeGoogle{}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	now := time.Unix(1_800_000_000, 0)
	svc := newTestService(t)
	h := &googleHarness{fake: fake, now: now}
	h.g = &GoogleLogin{
		ClientID:     testClientID,
		ClientSecret: "shh",
		RedirectURL:  "https://crowsnest.example.com/auth/google/callback",
		Users:        GoogleUsers{"alex@example.com": "alex", "friend@gmail.com": "friend"},
		AuthURL:      "https://accounts.example/auth",
		TokenURL:     srv.URL,
	}
	vlt, _ := vault.New("", filepath.Join(t.TempDir(), "k"))
	store, err := NewOIDCStore(filepath.Join(t.TempDir(), "oidc.json"), vlt)
	if err != nil {
		t.Fatal(err)
	}
	h.o = &OIDCLogin{Google: h.g, Service: svc, Store: store, HTTPClient: srv.Client(), Now: func() time.Time { return h.now }}
	return h
}

// start runs the start route and returns the state cookie and the query
// Google would have been sent.
func (h *googleHarness) start(t *testing.T) (*http.Cookie, url.Values) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.o.ServeStart(rec, httptest.NewRequest(http.MethodGet, GoogleStartPath, nil), GoogleProviderID)
	if rec.Code != http.StatusFound {
		t.Fatalf("start status = %d", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), "https://accounts.example/auth?") {
		t.Fatalf("start redirected to %q", rec.Header().Get("Location"))
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == oauthStateCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != oauthCookiePath {
		t.Fatalf("state cookie = %+v", cookie)
	}
	return cookie, loc.Query()
}

func (h *googleHarness) goodClaims(q url.Values) map[string]any {
	return map[string]any{
		"iss": "https://accounts.google.com", "aud": testClientID, "azp": testClientID,
		"exp": h.now.Add(time.Hour).Unix(), "iat": h.now.Unix(), "nonce": q.Get("nonce"),
		"email": "Alex@Example.com", "email_verified": true, "sub": "1234",
	}
}

func (h *googleHarness) callback(t *testing.T, cookie *http.Cookie, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, GoogleCallbackPath+"?"+query, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.o.ServeCallback(rec, req, GoogleProviderID)
	return rec
}

func sessionFrom(t *testing.T, svc *Service, rec *httptest.ResponseRecorder) (Session, bool) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			s, err := svc.Sessions.Decode(c.Value)
			if err != nil {
				t.Fatalf("session cookie does not decode: %v", err)
			}
			return s, true
		}
	}
	return Session{}, false
}

func TestGoogleLogin_FullFlow(t *testing.T) {
	h := newGoogleHarness(t)
	cookie, q := h.start(t)

	for k, want := range map[string]string{
		"client_id": testClientID, "redirect_uri": h.g.RedirectURL, "response_type": "code",
		"scope": "openid email", "code_challenge_method": "S256",
	} {
		if q.Get(k) != want {
			t.Errorf("auth request %s = %q, want %q", k, q.Get(k), want)
		}
	}
	h.fake.claims = h.goodClaims(q)

	rec := h.callback(t, cookie, "code=abc&state="+url.QueryEscape(q.Get("state")))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("callback = %d %q, want 303 /", rec.Code, rec.Header().Get("Location"))
	}
	s, ok := sessionFrom(t, h.o.Service, rec)
	if !ok || s.Username != "alex" {
		t.Fatalf("session = %+v (ok=%v), want user alex", s, ok)
	}

	// The token request carried the code, the secret, and a PKCE verifier
	// that hashes to the challenge sent in the browser redirect.
	f := h.fake.form
	if f.Get("code") != "abc" || f.Get("client_secret") != "shh" || f.Get("grant_type") != "authorization_code" ||
		f.Get("redirect_uri") != h.g.RedirectURL {
		t.Fatalf("token request form = %v", f)
	}
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") {
		t.Fatal("code_verifier does not match code_challenge")
	}

	// The state cookie is cleared, so the same callback can't be replayed.
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == oauthStateCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("state cookie was not cleared")
	}
}

func TestGoogleLogin_Refusals(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(h *googleHarness, claims map[string]any)
		query    func(state string) string
		cookie   func(c *http.Cookie) *http.Cookie
		wantCode string
		noToken  bool // the token endpoint must not even be called
	}{
		{name: "not on allowlist", mutate: func(_ *googleHarness, c map[string]any) { c["email"] = "stranger@gmail.com" }, wantCode: LoginErrorNotAllowed},
		{name: "email unverified", mutate: func(_ *googleHarness, c map[string]any) { c["email_verified"] = false }, wantCode: LoginErrorFailed},
		{name: "email_verified string false", mutate: func(_ *googleHarness, c map[string]any) { c["email_verified"] = "false" }, wantCode: LoginErrorFailed},
		// strings.ToLower folds U+0130 to "i": without the ASCII check this would sign in as friend.
		{name: "non-ASCII look-alike email", mutate: func(_ *googleHarness, c map[string]any) { c["email"] = "fr\u0130end@gmail.com" }, wantCode: LoginErrorFailed},
		{name: "no email", mutate: func(_ *googleHarness, c map[string]any) { delete(c, "email") }, wantCode: LoginErrorFailed},
		{name: "wrong issuer", mutate: func(_ *googleHarness, c map[string]any) { c["iss"] = "https://evil.example" }, wantCode: LoginErrorFailed},
		{name: "wrong audience", mutate: func(_ *googleHarness, c map[string]any) { c["aud"] = "other-client"; c["azp"] = "other-client" }, wantCode: LoginErrorFailed},
		{name: "multi audience, azp elsewhere", mutate: func(_ *googleHarness, c map[string]any) {
			c["aud"] = []string{testClientID, "other"}
			c["azp"] = "other"
		}, wantCode: LoginErrorFailed},
		{name: "expired token", mutate: func(h *googleHarness, c map[string]any) { c["exp"] = h.now.Add(-time.Hour).Unix() }, wantCode: LoginErrorFailed},
		{name: "issued in the future", mutate: func(h *googleHarness, c map[string]any) { c["iat"] = h.now.Add(time.Hour).Unix() }, wantCode: LoginErrorFailed},
		{name: "nonce mismatch", mutate: func(_ *googleHarness, c map[string]any) { c["nonce"] = "other" }, wantCode: LoginErrorFailed},
		{name: "no nonce", mutate: func(_ *googleHarness, c map[string]any) { delete(c, "nonce") }, wantCode: LoginErrorFailed},
		{name: "token endpoint error", mutate: func(h *googleHarness, _ map[string]any) { h.fake.status = http.StatusBadRequest }, wantCode: LoginErrorFailed},
		{name: "no id_token", mutate: func(h *googleHarness, _ map[string]any) { h.fake.noIDTok = true }, wantCode: LoginErrorFailed},
		{name: "state mismatch", query: func(string) string { return "code=abc&state=forged" }, wantCode: LoginErrorExpired, noToken: true},
		{name: "no code", query: func(s string) string { return "state=" + url.QueryEscape(s) }, wantCode: LoginErrorFailed, noToken: true},
		{name: "google error", query: func(s string) string { return "error=access_denied&state=" + url.QueryEscape(s) }, wantCode: LoginErrorDenied, noToken: true},
		{name: "no state cookie", cookie: func(*http.Cookie) *http.Cookie { return nil }, wantCode: LoginErrorExpired, noToken: true},
		{name: "tampered state cookie", cookie: func(c *http.Cookie) *http.Cookie {
			d := *c
			d.Value = "x" + d.Value[1:]
			return &d
		}, wantCode: LoginErrorExpired, noToken: true},
		{name: "session cookie passed as state", cookie: func(c *http.Cookie) *http.Cookie {
			m := NewSessionManager([]byte("test-secret"), time.Hour) // same secret as newTestService
			sess, _ := m.New("alex")
			tok, _ := m.Encode(sess)
			return &http.Cookie{Name: oauthStateCookie, Value: tok}
		}, wantCode: LoginErrorExpired, noToken: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newGoogleHarness(t)
			cookie, q := h.start(t)
			h.fake.claims = h.goodClaims(q)
			if tc.mutate != nil {
				tc.mutate(h, h.fake.claims)
			}
			query := "code=abc&state=" + url.QueryEscape(q.Get("state"))
			if tc.query != nil {
				query = tc.query(q.Get("state"))
			}
			if tc.cookie != nil {
				cookie = tc.cookie(cookie)
			}
			rec := h.callback(t, cookie, query)
			want := "/login?error=" + tc.wantCode
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
				t.Fatalf("callback = %d %q, want 303 %q", rec.Code, rec.Header().Get("Location"), want)
			}
			if _, ok := sessionFrom(t, h.o.Service, rec); ok {
				t.Fatal("a session cookie was set on a refused sign-in")
			}
			if tc.noToken && h.fake.requests != 0 {
				t.Fatalf("token endpoint called %d times, want 0", h.fake.requests)
			}
		})
	}
}

func TestGoogleLogin_ExpiredState(t *testing.T) {
	h := newGoogleHarness(t)
	cookie, q := h.start(t)
	h.fake.claims = h.goodClaims(q)
	h.now = h.now.Add(oauthStateTTL + time.Second)
	h.fake.claims["exp"] = h.now.Add(time.Hour).Unix()
	rec := h.callback(t, cookie, "code=abc&state="+url.QueryEscape(q.Get("state")))
	if rec.Header().Get("Location") != "/login?error="+LoginErrorExpired {
		t.Fatalf("callback with an old state cookie redirected to %q", rec.Header().Get("Location"))
	}
}

func TestGoogleLogin_RateLimited(t *testing.T) {
	h := newGoogleHarness(t)
	h.o.Service.LoginLimiter = NewLimiter(1, time.Minute)
	h.callback(t, nil, "code=x&state=y")
	rec := h.callback(t, nil, "code=x&state=y")
	if rec.Header().Get("Location") != "/login?error="+LoginErrorRateLimit {
		t.Fatalf("second callback redirected to %q, want rate limited", rec.Header().Get("Location"))
	}
}

func TestGoogleLogin_StartURLUsesRedirectOrigin(t *testing.T) {
	g := &GoogleLogin{RedirectURL: "https://crowsnest.example.com/auth/google/callback"}
	if got := g.StartURL(); got != "https://crowsnest.example.com/auth/google/start" {
		t.Fatalf("StartURL() = %q", got)
	}
}

func TestParseGoogleUsers(t *testing.T) {
	users, err := ParseGoogleUsers(" Alex=Alex@Example.com, friend=pal@gmail.com\nalex=other@example.org ")
	if err != nil {
		t.Fatalf("ParseGoogleUsers() error = %v", err)
	}
	want := GoogleUsers{"alex@example.com": "alex", "pal@gmail.com": "friend", "other@example.org": "alex"}
	if len(users) != len(want) {
		t.Fatalf("users = %v, want %v", users, want)
	}
	for k, v := range want {
		if users[k] != v {
			t.Fatalf("users[%q] = %q, want %q", k, users[k], v)
		}
	}

	for _, bad := range []string{"", "  ,", "alex", "=a@b.c", "alex=", "Bad Name=a@b.c", "x=notanemail", "a=x@y.z,b=x@y.z", "../x=a@b.c", "k=\u212aim@example.com", "i=fr\u0130end@gmail.com"} {
		if _, err := ParseGoogleUsers(bad); err == nil {
			t.Errorf("ParseGoogleUsers(%q) = nil error, want an error", bad)
		}
	}
}

func TestServeLogin_PasswordDisabled(t *testing.T) {
	svc := newTestService(t)
	svc.DisablePasswordLogin = true
	rec := doLogin(t, svc, "alice", "s3cret-password")
	if rec.Code != http.StatusForbidden || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("status = %d cookies = %v, want 403 and no cookie", rec.Code, rec.Result().Cookies())
	}
}

func TestServeLogin_UserWithoutHashIsUnknown(t *testing.T) {
	svc := newTestService(t)
	svc.Users["ghost"] = UserRecord{ValidAfter: time.Now()}
	if rec := doLogin(t, svc, "ghost", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a user with no password", rec.Code)
	}
}

func TestTokenClient_DoesNotFollowRedirects(t *testing.T) {
	var leaked int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked++ }))
	t.Cleanup(target.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)

	resp, err := tokenClient.Post(redirector.URL, "application/x-www-form-urlencoded", strings.NewReader("client_secret=shh"))
	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || leaked != 0 {
		t.Fatalf("status %d, redirect target hit %d time(s); want 307 and 0 (the client secret must not be re-sent)", resp.StatusCode, leaked)
	}
}

// signIn runs one Google sign-in with the given subject and email and returns the signed-in user ("" if refused).
func (h *googleHarness) signIn(t *testing.T, sub, email string) string {
	t.Helper()
	cookie, q := h.start(t)
	claims := h.goodClaims(q)
	claims["sub"], claims["email"] = sub, email
	h.fake.claims = claims
	rec := h.callback(t, cookie, "code=abc&state="+url.QueryEscape(q.Get("state")))
	if s, ok := sessionFrom(t, h.o.Service, rec); ok {
		return s.Username
	}
	return ""
}

func TestGoogleLogin_BoundToSubject(t *testing.T) {
	h := newGoogleHarness(t)
	if got := h.signIn(t, "1234", "alex@example.com"); got != "alex" {
		t.Fatalf("first sign-in = %q, want alex", got)
	}
	// Another Google account that now holds the same address is not alex.
	if got := h.signIn(t, "9999", "alex@example.com"); got != "" {
		t.Errorf("a different subject with the same email signed in as %q", got)
	}
	// The same account still signs in after Google reports a different address, as long as alex may use Google.
	if got := h.signIn(t, "1234", "other@example.com"); got != "alex" {
		t.Errorf("the linked subject with a changed email = %q, want alex", got)
	}
	// Re-pointing alex at another address drops the link, so the new account can link.
	if err := h.o.Store.UnlinkProvider(GoogleProviderID, "alex"); err != nil {
		t.Fatal(err)
	}
	if got := h.signIn(t, "9999", "alex@example.com"); got != "alex" {
		t.Errorf("after unlinking, the new subject = %q, want alex", got)
	}
}

func TestGoogleLogin_RefusesUnverifiableIDToken(t *testing.T) {
	h := newGoogleHarness(t)
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One RSA key that did not sign the fake's token.
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": "k", "n": base64.RawURLEncoding.EncodeToString(make([]byte, 256)), "e": "AQAB"}}})
	}))
	defer keys.Close()
	h.g.JWKSURL = keys.URL
	h.o.HTTPClient = keys.Client()
	if got := h.signIn(t, "1234", "alex@example.com"); got != "" {
		t.Fatalf("an ID token whose signature can't be checked signed in as %q", got)
	}
}
