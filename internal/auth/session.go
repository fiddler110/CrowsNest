package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultSessionTTL is how long a session cookie stays valid after login.
// Kept short since CrowsNest sessions are just used to start/stop/check a
// game server, not for long browsing — an expired session is a cheap
// re-login, not a real inconvenience.
const DefaultSessionTTL = 3 * time.Hour

// SessionCookieName is the cookie a signed session is carried in. With secure
// cookies on it takes the __Host- prefix (see UseSecureCookieName), which makes
// a browser refuse it unless it was set over HTTPS for exactly this host, so a
// sibling subdomain cannot plant or overwrite it.
var SessionCookieName = "crowsnest_session"

// UseSecureCookieName switches the session cookie to its __Host- name (secure
// true) or back. Call it once at startup, before serving.
func UseSecureCookieName(secure bool) {
	SessionCookieName = "crowsnest_session"
	if secure {
		SessionCookieName = "__Host-crowsnest_session"
	}
}

var (
	ErrInvalidSession = errors.New("auth: invalid session")
	ErrSessionExpired = errors.New("auth: session expired")
	ErrSessionRevoked = errors.New("auth: session revoked")
)

// Session is the payload signed into the session cookie. Everything needed to
// verify it is in this struct; when the manager has a Registry, the session's
// ID must also still be listed there.
type Session struct {
	// ID names the session in the SessionStore, so one device can be signed out on its own.
	ID        string    `json:"sid,omitempty"`
	Username  string    `json:"user"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	CSRFToken string    `json:"csrf"`
}

// SessionManager signs and verifies session cookies with an HMAC-SHA256
// tag. Stateless — no server-side session store — but Decode still rejects
// a session pre-dating its user's ValidAfter marker when Users is set,
// giving per-user revocation (see RevokeSessions) without needing one.
// Rotating the secret remains the blunt "revoke absolutely everyone" tool.
type SessionManager struct {
	secret []byte
	ttl    time.Duration

	// AbsoluteMax, when longer than the idle time, turns on sliding sessions: activity renews a session's
	// cookie for another idle period, but never past this long after sign-in. Zero keeps a fixed lifetime.
	AbsoluteMax time.Duration
	// Secure marks the renewed cookie Secure (server.secure_cookies).
	Secure bool

	// Users, when set, is consulted by Decode to reject sessions revoked via
	// RevokeSessions. Left nil (the zero value) by default; nil-safe.
	Users Users

	// Store, when set, takes the place of Users and follows changes to the
	// users file while running.
	Store *UserStore

	// Allowed, when set, must return true for a session's username or Decode
	// rejects it as revoked. CrowsNest sets it to "has a password (and password
	// sign-in is on) or is on the Google allowlist", so taking someone off the
	// allowlist and restarting ends their sessions without revoke-sessions.
	Allowed func(username string) bool

	// Registry, when set, is the server-side list of live sessions: Decode rejects a session whose ID is not
	// in it (signed out from the profile page, or made before the registry existed).
	Registry *SessionStore
}

func NewSessionManager(secret []byte, ttl time.Duration) *SessionManager {
	return &SessionManager{secret: secret, ttl: ttl}
}

// New creates a fresh session for username with a new random CSRF token.
func (m *SessionManager) New(username string) (Session, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return Session{}, fmt.Errorf("auth: generate csrf token: %w", err)
	}
	id, err := NewSessionID()
	if err != nil {
		return Session{}, err
	}
	now := time.Now().UTC()
	return Session{
		ID:        id,
		Username:  username,
		IssuedAt:  now,
		ExpiresAt: now.Add(m.ttl),
		CSRFToken: hex.EncodeToString(token),
	}, nil
}

// Encode signs s into an opaque cookie value.
func (m *SessionManager) Encode(s Session) (string, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("auth: marshal session: %w", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	mac := m.sign(encodedPayload)
	return encodedPayload + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

// Decode verifies and parses a cookie value produced by Encode, rejecting a
// bad signature or an expired session.
func (m *SessionManager) Decode(token string) (Session, error) {
	encodedPayload, encodedMAC, ok := strings.Cut(token, ".")
	if !ok {
		return Session{}, ErrInvalidSession
	}
	gotMAC, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil {
		return Session{}, ErrInvalidSession
	}
	wantMAC := m.sign(encodedPayload)
	if !hmac.Equal(gotMAC, wantMAC) {
		return Session{}, ErrInvalidSession
	}

	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return Session{}, ErrInvalidSession
	}
	var s Session
	if err := json.Unmarshal(payload, &s); err != nil {
		return Session{}, ErrInvalidSession
	}
	if time.Now().UTC().After(s.ExpiresAt) {
		return Session{}, ErrSessionExpired
	}
	if rec, ok := m.lookupUser(s.Username); ok && !rec.ValidAfter.IsZero() && s.IssuedAt.Before(rec.ValidAfter) {
		return Session{}, ErrSessionRevoked
	}
	if m.Allowed != nil && !m.Allowed(s.Username) {
		return Session{}, ErrSessionRevoked
	}
	if m.Registry != nil && (s.ID == "" || !m.Registry.Touch(s.ID, time.Now().UTC())) {
		return Session{}, ErrSessionRevoked
	}
	return s, nil
}

// Renew extends a session that has been used for a while: its cookie is re-issued with another idle period, capped
// at AbsoluteMax after sign-in. It returns the session as it now stands. It does nothing unless sliding sessions are
// on, and only acts once a quarter of the idle period has passed, so a busy page is not re-signed on every request.
func (m *SessionManager) Renew(w http.ResponseWriter, s Session) Session {
	if m.AbsoluteMax <= m.ttl || w == nil {
		return s
	}
	now := time.Now().UTC()
	if s.ExpiresAt.Sub(now) > m.ttl*3/4 {
		return s
	}
	next := now.Add(m.ttl)
	if limit := s.IssuedAt.Add(m.AbsoluteMax); next.After(limit) {
		next = limit
	}
	if !next.After(s.ExpiresAt) {
		return s
	}
	s.ExpiresAt = next
	token, err := m.Encode(s)
	if err != nil {
		return s
	}
	if m.Registry != nil {
		m.Registry.Extend(s.ID, next)
	}
	// #nosec G124 -- same attributes as the cookie set at sign-in; Secure follows server.secure_cookies
	http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: token, Path: "/", HttpOnly: true,
		Secure: m.Secure, SameSite: http.SameSiteLaxMode, Expires: next})
	return s
}

func (m *SessionManager) sign(encodedPayload string) []byte {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(encodedPayload))
	return mac.Sum(nil)
}

func (m *SessionManager) lookupUser(name string) (UserRecord, bool) {
	if m.Store != nil {
		return m.Store.Lookup(name)
	}
	rec, ok := m.Users[name]
	return rec, ok
}
