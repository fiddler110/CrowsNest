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

// maxLoginBodyBytes caps the /login request body. It's unauthenticated, so
// without a cap a client could force arbitrarily large allocations via
// json.Decode before the rate limiter even has a chance to kick in.
const maxLoginBodyBytes = 4096

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
	Users Users
	// Store, when set, takes the place of Users and follows changes to the
	// users file while running.
	Store          *UserStore
	Sessions       *SessionManager
	LoginLimiter   *Limiter
	TrustedProxies []*net.IPNet

	// SecureCookies marks the session cookie Secure; set true once serving
	// over TLS or behind a TLS-terminating reverse proxy.
	SecureCookies bool

	// DisablePasswordLogin turns off POST /login with a username and
	// password (e.g. Google sign-in only): every password attempt is refused
	// before any credential is looked at. The zero value keeps it on.
	DisablePasswordLogin bool
}

// passwordLoginDisabled is the 403 body when password sign-in is off.
const passwordLoginDisabled = "password sign-in is disabled"

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
	if s.DisablePasswordLogin {
		http.Error(w, passwordLoginDisabled, http.StatusForbidden)
		return
	}
	ip := ClientIP(r, s.TrustedProxies)
	if s.LoginLimiter != nil && !s.LoginLimiter.Allow(ip) {
		http.Error(w, "too many login attempts, try again later", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	username := strings.ToLower(strings.TrimSpace(req.Username))

	var record UserRecord
	var known bool
	if s.Store != nil {
		record, known = s.Store.Lookup(username)
	} else {
		record, known = s.Users[username]
	}
	// A user with no hash (e.g. a Google-only user with just a revocation
	// marker) has no password: treat them exactly like an unknown name.
	known = known && record.Hash != ""
	hash := record.Hash
	if !known {
		hash = dummyHash
	}
	validPassword := VerifyPassword(hash, req.Password)
	if !known || !validPassword {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	session, err := s.newSession(w, username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(loginResponse{CSRFToken: session.CSRFToken})
}

// startSession signs a new session for username and sets its cookie; used by
// sign-in methods that redirect rather than answer JSON (Google).
func (s *Service) startSession(w http.ResponseWriter, username string) error {
	_, err := s.newSession(w, username)
	return err
}

func (s *Service) newSession(w http.ResponseWriter, username string) (Session, error) {
	session, err := s.Sessions.New(username)
	if err != nil {
		return Session{}, err
	}
	token, err := s.Sessions.Encode(session)
	if err != nil {
		return Session{}, err
	}

	// #nosec G124 -- HttpOnly and SameSite=Lax are always set; Secure follows server.secure_cookies, because a
	// plain-HTTP LAN deployment would never get a Secure cookie back from the browser.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		Expires:  session.ExpiresAt,
	})
	return session, nil
}

// ServeLogout clears the session cookie. Idempotent; doesn't require a
// valid session (there's no server-side state to invalidate).
func (s *Service) ServeLogout(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- clears the cookie; same attributes as the one set at login
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
