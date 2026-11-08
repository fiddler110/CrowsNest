package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
)

// Google sign-in (OpenID Connect authorization code flow, server side).
//
// The browser is sent to Google with a random state, a nonce and a PKCE
// challenge; those three are kept in a short-lived cookie that is HMAC-signed
// with the session secret, so CrowsNest stays stateless. On the callback,
// CrowsNest exchanges the code for tokens directly with Google's token
// endpoint over TLS (with its client secret and the PKCE verifier) and reads
// the ID token from that response. OpenID Connect Core 1.0 §3.1.3.7 allows
// TLS server validation in place of checking the token's signature when the
// ID token comes straight from the token endpoint like this, so no JWKS
// fetching or JWT library is needed. The issuer, audience, expiry, nonce and
// email_verified claims are all still checked.
//
// Who may sign in is an explicit allowlist mapping each Google email to a
// CrowsNest username (GoogleUsers). After that, the user gets the same signed
// session cookie as a password login: CSRF, per-user revocation
// (revoke-sessions) and audit lines all work by username.

const (
	// GoogleStartPath and GoogleCallbackPath are the two routes Google sign-in
	// uses. The callback must be registered as an authorized redirect URI on the
	// OAuth client (with the scheme and host from GoogleLogin.RedirectURL).
	GoogleStartPath    = "/auth/google/start"
	GoogleCallbackPath = "/auth/google/callback"

	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token" // #nosec G101 -- an endpoint URL, not a credential

	oauthStateCookie = "crowsnest_oauth"
	oauthStateTTL    = 10 * time.Minute
	maxTokenResponse = 1 << 20
	clockSkew        = 2 * time.Minute
)

// googleIssuers are the two issuer spellings Google documents for ID tokens.
var googleIssuers = map[string]bool{"https://accounts.google.com": true, "accounts.google.com": true}

// Login page error codes. The callback only ever redirects with one of these
// fixed codes, never with text from the request, so nothing user-supplied is
// reflected on the login page.
const (
	LoginErrorDenied     = "google_denied"     // the user cancelled, or Google returned an error
	LoginErrorExpired    = "google_expired"    // the state cookie was missing, expired or did not match
	LoginErrorNotAllowed = "google_notallowed" // signed in fine, but that email isn't on the allowlist
	LoginErrorFailed     = "google_failed"     // token exchange or ID token validation failed
	LoginErrorRateLimit  = "rate_limited"
)

// GoogleUsers maps a lowercased Google account email to a CrowsNest username.
type GoogleUsers map[string]string

var (
	usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	// ASCII only: strings.ToLower folds some non-ASCII runes to ASCII (U+212A KELVIN SIGN to "k"),
	// which would let a look-alike address match an allowlisted one.
	emailPattern = regexp.MustCompile(`^[!-+\--<>?A-~]+@[!-+\--<>?A-~]+\.[!-+\--<>?A-~]+$`)
)

// ParseGoogleUsers parses an allowlist of "name=email" pairs separated by
// commas, spaces or newlines, e.g. "scott=scott@gmail.com,friend=f@gmail.com".
// Names are CrowsNest usernames (lowercase letters, digits, '-' and '_'); one
// name may have several emails, but each email maps to exactly one name.
func ParseGoogleUsers(spec string) (GoogleUsers, error) {
	users := GoogleUsers{}
	fields := strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' })
	for _, f := range fields {
		// Check for non-ASCII before lowercasing, which would fold some look-alikes to ASCII.
		for _, r := range f {
			if r > unicode.MaxASCII {
				return nil, fmt.Errorf("auth: google users: %q has non-ASCII characters", f)
			}
		}
		name, email, ok := strings.Cut(f, "=")
		name, email = strings.ToLower(strings.TrimSpace(name)), strings.ToLower(strings.TrimSpace(email))
		if !ok || name == "" || email == "" {
			return nil, fmt.Errorf("auth: google users: %q is not name=email", f)
		}
		if !usernamePattern.MatchString(name) {
			return nil, fmt.Errorf("auth: google users: username %q must match %s", name, usernamePattern)
		}
		if !emailPattern.MatchString(email) {
			return nil, fmt.Errorf("auth: google users: %q is not an email address", email)
		}
		if other, dup := users[email]; dup && other != name {
			return nil, fmt.Errorf("auth: google users: %s is listed for both %q and %q", email, other, name)
		}
		users[email] = name
	}
	if len(users) == 0 {
		return nil, errors.New("auth: google users: the allowlist is empty")
	}
	return users, nil
}

// GoogleLogin serves Google sign-in. Construct it in main and hand it to the
// web app; Service supplies the session/cookie/rate-limit machinery.
type GoogleLogin struct {
	ClientID     string
	ClientSecret string
	// RedirectURL is the absolute callback URL registered with Google, e.g.
	// https://crowsnest.example.com/auth/google/callback.
	RedirectURL string
	Users       GoogleUsers
	// Store, when set, adds the Google emails recorded in the users file
	// (managed from the dashboard) to the Users allowlist.
	Store   *UserStore
	Service *Service

	// Overridable for tests; default to Google's endpoints and a 10s client.
	AuthURL    string
	TokenURL   string
	HTTPClient *http.Client
	Now        func() time.Time
}

// StartURL is the absolute URL of the start route on the redirect URL's
// origin. The login page links there, so the state cookie is always set on
// the same host the callback comes back to, even when the login page was
// reached through another hostname that proxies to CrowsNest.
func (g *GoogleLogin) StartURL() string {
	u, err := url.Parse(g.RedirectURL)
	if err != nil {
		return GoogleStartPath
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: GoogleStartPath}).String()
}

type oauthState struct {
	State     string `json:"s"`
	Nonce     string `json:"n"`
	Verifier  string `json:"v"`
	ExpiresAt int64  `json:"e"`
}

// ServeStart sends the browser to Google's consent screen.
func (g *GoogleLogin) ServeStart(w http.ResponseWriter, r *http.Request) {
	st := oauthState{State: randomToken(), Nonce: randomToken(), Verifier: randomToken(), ExpiresAt: g.now().Add(oauthStateTTL).Unix()}
	if st.State == "" || st.Nonce == "" || st.Verifier == "" {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	value, err := g.Service.Sessions.signPurpose("oauth-state", st)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// #nosec G124 -- HttpOnly and SameSite=Lax always; Secure follows server.secure_cookies. Lax (not Strict) is
	// required: the callback is a top-level navigation coming back from accounts.google.com.
	http.SetCookie(w, &http.Cookie{
		Name: oauthStateCookie, Value: value, Path: "/auth/google/", MaxAge: int(oauthStateTTL.Seconds()),
		HttpOnly: true, Secure: g.Service.SecureCookies, SameSite: http.SameSiteLaxMode,
	})
	challenge := sha256.Sum256([]byte(st.Verifier))
	q := url.Values{
		"client_id":             {g.ClientID},
		"redirect_uri":          {g.RedirectURL},
		"response_type":         {"code"},
		"scope":                 {"openid email"},
		"state":                 {st.State},
		"nonce":                 {st.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
		"prompt":                {"select_account"},
		"access_type":           {"online"},
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, g.authURL()+"?"+q.Encode(), http.StatusFound)
}

// ServeCallback finishes sign-in: checks the state, exchanges the code,
// validates the ID token, checks the allowlist and sets the session cookie.
func (g *GoogleLogin) ServeCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ip := ClientIP(r, g.Service.TrustedProxies)
	if g.Service.LoginLimiter != nil && !g.Service.LoginLimiter.Allow(ip) {
		g.fail(w, r, LoginErrorRateLimit)
		return
	}

	st, ok := g.readState(r)
	g.clearState(w) // single use, whatever happens next
	q := r.URL.Query()
	if q.Get("error") != "" {
		g.fail(w, r, LoginErrorDenied)
		return
	}
	if !ok || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		g.fail(w, r, LoginErrorExpired)
		return
	}
	code := q.Get("code")
	if code == "" {
		g.fail(w, r, LoginErrorFailed)
		return
	}

	claims, err := g.exchange(r.Context(), code, st)
	if err != nil {
		log.Printf("auth: google sign-in failed: %v", err)
		g.fail(w, r, LoginErrorFailed)
		return
	}
	username, allowed := g.Lookup(claims.email)
	if !allowed {
		log.Printf("audit: google sign-in refused for %q (not on the allowlist)", claims.email)
		g.fail(w, r, LoginErrorNotAllowed)
		return
	}
	if err := g.Service.startSession(w, username); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("audit: %s signed in with Google (%q)", username, claims.email)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (g *GoogleLogin) fail(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(code), http.StatusSeeOther)
}

func (g *GoogleLogin) readState(r *http.Request) (oauthState, bool) {
	c, err := r.Cookie(oauthStateCookie)
	if err != nil {
		return oauthState{}, false
	}
	var st oauthState
	if err := g.Service.Sessions.verifyPurpose("oauth-state", c.Value, &st); err != nil {
		return oauthState{}, false
	}
	if st.State == "" || st.Nonce == "" || st.Verifier == "" || g.now().Unix() > st.ExpiresAt {
		return oauthState{}, false
	}
	return st, true
}

func (g *GoogleLogin) clearState(w http.ResponseWriter) {
	// #nosec G124 -- clears the state cookie; same attributes as when it was set
	http.SetCookie(w, &http.Cookie{
		Name: oauthStateCookie, Value: "", Path: "/auth/google/", MaxAge: -1, Expires: time.Unix(0, 0),
		HttpOnly: true, Secure: g.Service.SecureCookies, SameSite: http.SameSiteLaxMode,
	})
}

type idClaims struct {
	email string
}

type tokenResponse struct {
	IDToken string `json:"id_token"`
}

type rawClaims struct {
	Iss           string          `json:"iss"`
	Aud           json.RawMessage `json:"aud"`
	Azp           string          `json:"azp"`
	Exp           json.Number     `json:"exp"`
	Iat           json.Number     `json:"iat"`
	Nonce         string          `json:"nonce"`
	Email         string          `json:"email"`
	EmailVerified json.RawMessage `json:"email_verified"`
}

func (g *GoogleLogin) exchange(ctx context.Context, code string, st oauthState) (idClaims, error) {
	form := url.Values{
		"code":          {code},
		"client_id":     {g.ClientID},
		"client_secret": {g.ClientSecret},
		"redirect_uri":  {g.RedirectURL},
		"grant_type":    {"authorization_code"},
		"code_verifier": {st.Verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return idClaims{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := g.client().Do(req) // #nosec G704 -- the token URL is a constant (or a test override), never request data
	if err != nil {
		return idClaims{}, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return idClaims{}, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return idClaims{}, fmt.Errorf("token endpoint answered %d", resp.StatusCode)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.IDToken == "" {
		return idClaims{}, errors.New("token response has no id_token")
	}
	return g.validateIDToken(tr.IDToken, st.Nonce)
}

func (g *GoogleLogin) validateIDToken(token, wantNonce string) (idClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return idClaims{}, errors.New("id_token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return idClaims{}, errors.New("id_token payload is not base64url")
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	var c rawClaims
	if err := dec.Decode(&c); err != nil {
		return idClaims{}, errors.New("id_token payload is not JSON")
	}
	if !googleIssuers[c.Iss] {
		return idClaims{}, fmt.Errorf("id_token issuer %q is not Google", c.Iss)
	}
	if !audienceOK(c.Aud, c.Azp, g.ClientID) {
		return idClaims{}, errors.New("id_token audience is not this client")
	}
	now := g.now()
	exp, err1 := c.Exp.Int64()
	iat, err2 := c.Iat.Int64()
	if err1 != nil || err2 != nil {
		return idClaims{}, errors.New("id_token exp/iat missing or not integers")
	}
	if now.After(time.Unix(exp, 0).Add(clockSkew)) {
		return idClaims{}, errors.New("id_token expired")
	}
	if time.Unix(iat, 0).After(now.Add(clockSkew)) {
		return idClaims{}, errors.New("id_token issued in the future")
	}
	if wantNonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(wantNonce)) != 1 {
		return idClaims{}, errors.New("id_token nonce does not match")
	}
	if !emailVerified(c.EmailVerified) {
		return idClaims{}, errors.New("google account email is not verified")
	}
	email := strings.TrimSpace(c.Email)
	if email == "" {
		return idClaims{}, errors.New("id_token has no email (is the email scope granted?)")
	}
	if !emailPattern.MatchString(email) {
		return idClaims{}, fmt.Errorf("id_token email %q is not a plain ASCII address", email)
	}
	email = strings.ToLower(email)
	return idClaims{email: email}, nil
}

// audienceOK accepts aud as a string or an array. With several audiences the
// authorized party (azp) must be this client, per OpenID Connect Core §3.1.3.7.
func audienceOK(raw json.RawMessage, azp, clientID string) bool {
	var auds []string
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		auds = []string{one}
	} else if err := json.Unmarshal(raw, &auds); err != nil || len(auds) == 0 {
		return false
	}
	if !slices.Contains(auds, clientID) {
		return false
	}
	if len(auds) > 1 {
		return azp == clientID
	}
	return azp == "" || azp == clientID
}

// emailVerified accepts true or "true": Google has used both encodings.
func emailVerified(raw json.RawMessage) bool {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var s string
	return json.Unmarshal(raw, &s) == nil && s == "true"
}

func (g *GoogleLogin) authURL() string {
	if g.AuthURL != "" {
		return g.AuthURL
	}
	return googleAuthURL
}

func (g *GoogleLogin) tokenURL() string {
	if g.TokenURL != "" {
		return g.TokenURL
	}
	return googleTokenURL
}

func (g *GoogleLogin) client() *http.Client {
	if g.HTTPClient != nil {
		return g.HTTPClient
	}
	return tokenClient
}

// tokenClient never follows redirects: a 307/308 would re-send the POST body, client secret included,
// to wherever the Location header points.
var tokenClient = &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (g *GoogleLogin) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// signPurpose signs v as JSON with a key derived for one purpose, so a value
// minted for one use (here: the OAuth state cookie) can never pass as a
// session cookie or anything else signed with the same secret.
func (m *SessionManager) signPurpose(purpose string, v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(payload)
	return enc + "." + base64.RawURLEncoding.EncodeToString(m.purposeMAC(purpose, enc)), nil
}

func (m *SessionManager) verifyPurpose(purpose, value string, v any) error {
	enc, macPart, ok := strings.Cut(value, ".")
	if !ok {
		return ErrInvalidSession
	}
	got, err := base64.RawURLEncoding.DecodeString(macPart)
	if err != nil || !hmac.Equal(got, m.purposeMAC(purpose, enc)) {
		return ErrInvalidSession
	}
	payload, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return ErrInvalidSession
	}
	if json.Unmarshal(payload, v) != nil {
		return ErrInvalidSession
	}
	return nil
}

func (m *SessionManager) purposeMAC(purpose, enc string) []byte {
	key := hmac.New(sha256.New, m.secret)
	key.Write([]byte("crowsnest purpose key: " + purpose))
	mac := hmac.New(sha256.New, key.Sum(nil))
	mac.Write([]byte(enc))
	return mac.Sum(nil)
}

// Lookup returns the username a Google email may sign in as. The env
// allowlist is checked first, then the users file.
func (g *GoogleLogin) Lookup(email string) (string, bool) {
	email = strings.ToLower(email)
	if name, ok := g.Users[email]; ok {
		return name, true
	}
	if g.Store != nil {
		name, ok := g.Store.GoogleUsers()[email]
		return name, ok
	}
	return "", false
}

// Allows reports whether username is reachable by some Google account.
func (g *GoogleLogin) Allows(username string) bool {
	for _, n := range g.Users {
		if n == username {
			return true
		}
	}
	if g.Store != nil {
		if rec, ok := g.Store.Lookup(username); ok && rec.GoogleEmail != "" {
			return true
		}
	}
	return false
}
