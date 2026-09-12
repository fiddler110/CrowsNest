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
	"strings"
	"time"
)

// DefaultSessionTTL is how long a session cookie stays valid after login.
const DefaultSessionTTL = 24 * time.Hour

// SessionCookieName is the cookie a signed session is carried in.
const SessionCookieName = "crowsnest_session"

var (
	ErrInvalidSession = errors.New("auth: invalid session")
	ErrSessionExpired = errors.New("auth: session expired")
)

// Session is the payload signed into the session cookie. There is no
// server-side session store: everything needed to verify and use a session
// is in this struct.
type Session struct {
	Username  string    `json:"user"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	CSRFToken string    `json:"csrf"`
}

// SessionManager signs and verifies session cookies with an HMAC-SHA256
// tag. Stateless: revocation is only possible by rotating the secret, which
// invalidates every session at once.
type SessionManager struct {
	secret []byte
	ttl    time.Duration
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
	now := time.Now().UTC()
	return Session{
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
	return s, nil
}

func (m *SessionManager) sign(encodedPayload string) []byte {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(encodedPayload))
	return mac.Sum(nil)
}
