package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/vault"
)

type fakeIdP struct {
	srv   *httptest.Server
	nonce string
	sub   string
	email string
	extra map[string]any
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	f := &fakeIdP{sub: "sub-1", email: "ann@x.org"}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token",
			"code_challenge_methods_supported": []string{"S256"}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("client_secret") != "shh" || r.Form.Get("code_verifier") == "" {
			http.Error(w, "bad", 400)
			return
		}
		now := time.Now().Unix()
		claims := map[string]any{"iss": f.srv.URL, "aud": "cid", "exp": now + 300, "iat": now, "nonce": f.nonce, "sub": f.sub, "email": f.email, "email_verified": true}
		for k, v := range f.extra {
			claims[k] = v
		}
		b, _ := json.Marshal(claims)
		jwt := "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
		json.NewEncoder(w).Encode(map[string]string{"id_token": jwt})
	})
	return f
}

func TestDiscover(t *testing.T) {
	f := newFakeIdP(t)
	a, tok, err := Discover(context.Background(), nil, f.srv.URL+"/")
	if err != nil || a != f.srv.URL+"/auth" || tok != f.srv.URL+"/token" {
		t.Fatalf("Discover = %q %q %v", a, tok, err)
	}
	// A document naming another issuer is refused.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": "https://evil.example", "authorization_endpoint": "https://evil.example/a", "token_endpoint": "https://evil.example/t"})
	}))
	defer other.Close()
	if _, _, err := Discover(context.Background(), nil, other.URL); err == nil {
		t.Error("accepted a discovery document for another issuer")
	}
}

func TestOIDCSignInAndLinking(t *testing.T) {
	f := newFakeIdP(t)
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	if err := CreateUser(users, "ann", "h", "", RolePlayer); err != nil {
		t.Fatal(err)
	}
	if err := SetOIDCEmail(users, "ann", "Ann@X.org"); err != nil {
		t.Fatal(err)
	}
	us, _ := NewUserStore(users)
	vlt, _ := vault.New("", filepath.Join(dir, "k"))
	st, err := NewOIDCStore(filepath.Join(dir, "oidc.json"), vlt)
	if err != nil {
		t.Fatal(err)
	}
	authURL, tokenURL, _ := Discover(context.Background(), nil, f.srv.URL)
	p := OIDCProvider{ID: "idp", Name: "Test IdP", Issuer: f.srv.URL, ClientID: "cid", ClientSecret: "shh",
		RedirectURL: "http://localhost/auth/oidc/idp/callback", AuthURL: authURL, TokenURL: tokenURL, Enabled: true}
	if err := st.Put(p); err != nil {
		t.Fatal(err)
	}
	svc := &Service{Store: us, Sessions: NewSessionManager([]byte("0123456789abcdef0123456789abcdef"), time.Hour)}
	o := &OIDCLogin{Store: st, Users: us, Service: svc}

	signIn := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		o.ServeStart(rec, httptest.NewRequest("GET", "/auth/oidc/idp/start", nil), "idp")
		loc, _ := url.Parse(rec.Header().Get("Location"))
		q := loc.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "cid" {
			t.Fatalf("start redirect = %s", loc)
		}
		f.nonce = q.Get("nonce")
		req := httptest.NewRequest("GET", "/auth/oidc/idp/callback?code=c&state="+url.QueryEscape(q.Get("state")), nil)
		for _, c := range rec.Result().Cookies() {
			req.AddCookie(c)
		}
		out := httptest.NewRecorder()
		o.ServeCallback(out, req, "idp")
		return out
	}
	signedIn := func(rec *httptest.ResponseRecorder) bool {
		for _, c := range rec.Result().Cookies() {
			if c.Name == SessionCookieName && c.Value != "" {
				return true
			}
		}
		return false
	}

	// First sign-in links by verified email.
	if rec := signIn(); !signedIn(rec) || rec.Header().Get("Location") != "/" {
		t.Fatalf("first sign-in: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if u, ok := st.LinkedUser("idp", "sub-1"); !ok || u != "ann" {
		t.Fatalf("link = %q %v", u, ok)
	}
	// The same subject signs in even if its email changed.
	f.email = "renamed@x.org"
	if rec := signIn(); !signedIn(rec) {
		t.Fatal("linked subject refused after an email change")
	}
	// Another subject presenting ann's email can't take the account over.
	f.sub, f.email = "sub-2", "ann@x.org"
	if rec := signIn(); signedIn(rec) || !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Fatalf("a different subject with the same email got in: %s", rec.Header().Get("Location"))
	}
	// An unverified email never links.
	f.sub, f.extra = "sub-3", map[string]any{"email_verified": false}
	if rec := signIn(); signedIn(rec) {
		t.Fatal("unverified email signed in")
	}
	// A wrong state is refused, and a disabled provider 404s.
	rec := httptest.NewRecorder()
	o.ServeCallback(rec, httptest.NewRequest("GET", "/auth/oidc/idp/callback?code=c&state=x", nil), "idp")
	if signedIn(rec) {
		t.Fatal("signed in without a state cookie")
	}
	p.Enabled = false
	st.Put(p)
	rec = httptest.NewRecorder()
	o.ServeStart(rec, httptest.NewRequest("GET", "/", nil), "idp")
	if rec.Code != http.StatusNotFound {
		t.Errorf("disabled provider start = %d", rec.Code)
	}
	// The secret is sealed on disk; links survive a reload.
	raw, _ := readFile(filepath.Join(dir, "oidc.json"))
	if strings.Contains(raw, "shh") {
		t.Fatal("client secret stored in plain text")
	}
	st2, err := NewOIDCStore(filepath.Join(dir, "oidc.json"), vlt)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := st2.Get("idp"); got.ClientSecret != "shh" {
		t.Errorf("reloaded secret = %q", got.ClientSecret)
	}
	if u, _ := st2.LinkedUser("idp", "sub-1"); u != "ann" {
		t.Error("link lost on reload")
	}
}

func readFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}

func TestOIDCProviderIDGoogleReserved(t *testing.T) {
	p := OIDCProvider{ID: GoogleProviderID, Name: "x", Issuer: "https://idp.example", ClientID: "a", ClientSecret: "b",
		RedirectURL: OIDCCallbackPath(GoogleProviderID)}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("Validate() = %v, want the google id refused as reserved", err)
	}
}

// Discovery must not be pointed at the cloud metadata address (or other link-local, unspecified or multicast
// ones), by IP; loopback and LAN addresses stay allowed for an internal provider.
func TestSignInClientRefusesOddAddresses(t *testing.T) {
	for _, a := range []string{"169.254.169.254:80", "[fe80::1]:443", "0.0.0.0:80", "224.0.0.1:80", "[ff02::1]:80", "not-an-ip:80"} {
		if err := refuseOddAddress("tcp", a, nil); err == nil {
			t.Errorf("%s was allowed", a)
		}
	}
	for _, a := range []string{"127.0.0.1:8080", "192.168.1.10:443", "10.0.0.5:443", "93.184.216.34:443", "[::1]:80"} {
		if err := refuseOddAddress("tcp", a, nil); err != nil {
			t.Errorf("%s refused: %v", a, err)
		}
	}
	if _, _, err := Discover(context.Background(), nil, "https://169.254.169.254"); err == nil {
		t.Error("discovery reached the metadata address")
	}
}
