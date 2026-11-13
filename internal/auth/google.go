package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

// Google sign-in. The OpenID Connect flow itself lives in oidc.go and is shared
// with every other provider; this file is Google's settings and its allowlist.
//
// Who may sign in is an explicit allowlist mapping each Google email to a
// CrowsNest username (GoogleUsers, plus the users file). After that, the user
// gets the same signed session cookie as a password login: CSRF, per-user
// revocation (revoke-sessions) and audit lines all work by username.

const (
	// GoogleStartPath and GoogleCallbackPath are the two routes Google sign-in
	// uses. The callback must be registered as an authorized redirect URI on the
	// OAuth client (with the scheme and host from GoogleLogin.RedirectURL).
	GoogleStartPath    = "/auth/google/start"
	GoogleCallbackPath = "/auth/google/callback"

	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleJWKSURL  = "https://www.googleapis.com/oauth2/v3/certs"
	googleTokenURL = "https://oauth2.googleapis.com/token" // #nosec G101 -- an endpoint URL, not a credential

	oauthStateCookie = "crowsnest_oauth"
	// oauthCookiePath covers /auth/google/ and /auth/oidc/{id}/.
	oauthCookiePath  = "/auth/"
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
// commas, spaces or newlines, e.g. "alex=alex@example.com,friend=f@gmail.com".
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

// GoogleProviderID is the id of the built-in Google provider in the OIDC
// login code.
const GoogleProviderID = "google"

// GoogleLogin holds what is specific to signing in with Google: the OAuth
// client (changeable while the server runs), the allowlist of Google emails
// that may sign in, and Google's fixed endpoints. The protocol itself (state,
// PKCE, token exchange, ID token checks) is OIDCLogin's, which treats Google
// as one more provider.
type GoogleLogin struct {
	ClientID     string
	ClientSecret string
	// RedirectURL is the absolute callback URL registered with Google, e.g.
	// https://crowsnest.example.com/auth/google/callback.
	RedirectURL string
	Users       GoogleUsers
	// Store, when set, adds the Google emails recorded in the users file
	// (managed from the dashboard) to the Users allowlist.
	Store *UserStore

	// mu guards the client settings Reconfigure changes while the server runs.
	mu       sync.RWMutex
	disabled bool

	// Overridable for tests; default to Google's endpoints.
	AuthURL  string
	TokenURL string
	JWKSURL  string // overridable for tests; "" means Google's own
}

// creds returns the current client settings.
func (g *GoogleLogin) creds() (id, secret, redirect string) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.ClientID, g.ClientSecret, g.RedirectURL
}

// Active reports whether Google sign-in is switched on. A nil login is off.
func (g *GoogleLogin) Active() bool {
	if g == nil {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return !g.disabled
}

// Reconfigure replaces the client settings and turns sign-in on or off, at
// once and without a restart. The allowlist (Users and the users file) is
// unchanged.
func (g *GoogleLogin) Reconfigure(clientID, clientSecret, redirectURL string, enabled bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ClientID, g.ClientSecret, g.RedirectURL = clientID, clientSecret, redirectURL
	g.disabled = !enabled
}

// Provider describes Google as an OIDC provider, with the current settings.
func (g *GoogleLogin) Provider() OIDCProvider {
	id, secret, redirect := g.creds()
	p := OIDCProvider{
		ID: GoogleProviderID, Name: "Google", Issuer: "https://accounts.google.com",
		AuthURL: googleAuthURL, TokenURL: googleTokenURL, JWKSURL: googleJWKSURL,
		ClientID: id, ClientSecret: secret, RedirectURL: redirect, Enabled: g.Active(),
	}
	if g.AuthURL != "" {
		p.AuthURL = g.AuthURL
	}
	if g.TokenURL != "" {
		p.TokenURL = g.TokenURL
		p.JWKSURL = g.JWKSURL // a test server stands in for Google: its keys, or none
	}
	return p
}

// StartURL is the absolute URL of the start route on the redirect URL's
// origin. The login page links there, so the state cookie is always set on
// the same host the callback comes back to, even when the login page was
// reached through another hostname that proxies to CrowsNest.
func (g *GoogleLogin) StartURL() string {
	_, _, redirect := g.creds()
	u, err := url.Parse(redirect)
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
	Provider  string `json:"p,omitempty"` // the OIDC provider the flow began with
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
	Sub           string          `json:"sub"`
	Email         string          `json:"email"`
	EmailVerified json.RawMessage `json:"email_verified"`
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

// tokenClient never follows redirects: a 307/308 would re-send the POST body, client secret included,
// to wherever the Location header points.
//
// It also refuses to connect to link-local (cloud metadata at 169.254.169.254), unspecified and multicast
// addresses, which an identity provider is never at. The check runs on the address actually dialled, so a DNS
// name that points there is caught too. LAN and loopback addresses stay allowed: an internal provider is fine.
var tokenClient = &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, Control: refuseOddAddress}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	},
}

func refuseOddAddress(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("refusing to connect to %s: not an address a sign-in provider is at", address)
	}
	return nil
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
	if !g.Active() {
		return false
	}
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
