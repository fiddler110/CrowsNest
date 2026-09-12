package auth

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

// dummyHash is compared against on an unknown username so that a login
// attempt takes roughly the same time whether or not the username exists —
// otherwise bcrypt's absence on the "unknown user" path would let an
// attacker enumerate valid usernames by response latency.
var dummyHash = mustHash("crowsnest-timing-safety-dummy-password")

func mustHash(password string) string {
	hash, err := HashPassword(password)
	if err != nil {
		panic(err)
	}
	return hash
}

// Service bundles the pieces needed to serve login/logout: the user store,
// session signer, and a login-attempt rate limiter.
type Service struct {
	Users          Users
	Sessions       *SessionManager
	LoginLimiter   *Limiter
	TrustedProxies []*net.IPNet

	// SecureCookies marks the session cookie Secure; set true once serving
	// over TLS or behind a TLS-terminating reverse proxy.
	SecureCookies bool
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	CSRFToken string `json:"csrf_token"`
}

// ServeLogin verifies credentials and, on success, sets a signed session
// cookie and returns the session's CSRF token. Exempt from CSRF checking —
// it's what creates the token in the first place.
func (s *Service) ServeLogin(w http.ResponseWriter, r *http.Request) {
	ip := ClientIP(r, s.TrustedProxies)
	if s.LoginLimiter != nil && !s.LoginLimiter.Allow(ip) {
		http.Error(w, "too many login attempts, try again later", http.StatusTooManyRequests)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	username := strings.ToLower(strings.TrimSpace(req.Username))

	hash, known := s.Users[username]
	if !known {
		hash = dummyHash
	}
	validPassword := VerifyPassword(hash, req.Password)
	if !known || !validPassword {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	session, err := s.Sessions.New(username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token, err := s.Sessions.Encode(session)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		Expires:  session.ExpiresAt,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(loginResponse{CSRFToken: session.CSRFToken})
}

// ServeLogout clears the session cookie. Idempotent; doesn't require a
// valid session (there's no server-side state to invalidate).
func (s *Service) ServeLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusOK)
}
