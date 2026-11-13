package auth

import (
	"encoding/json"
	"errors"
	"github.com/fiddler110/crowsnest/internal/audit"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fiddler110/crowsnest/internal/mfa"
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
	Store        *UserStore
	Sessions     *SessionManager
	LoginLimiter *Limiter
	// UserLimiter throttles failed sign-ins per username, across every address, so guesses spread over many
	// addresses still add up. Nil turns it off.
	UserLimiter *Limiter
	// OnSignIn, when set, is told about every new session (after it is recorded). The panel uses it to notice a
	// sign-in from a browser or system the person has not used before.
	OnSignIn       func(SessionRecord)
	TrustedProxies []*net.IPNet

	// SecureCookies marks the session cookie Secure; set true once serving
	// over TLS or behind a TLS-terminating reverse proxy.
	SecureCookies bool

	// DisablePasswordLogin turns off POST /login with a username and
	// password (e.g. Google sign-in only): every password attempt is refused
	// before any credential is looked at. The zero value keeps it on.
	DisablePasswordLogin bool

	// passwordOverride is the dashboard's choice, which wins over
	// DisablePasswordLogin once set: 0 none, 1 password sign-in on, 2 off.
	passwordOverride atomic.Int32

	// MFA, when set, asks for a second factor after a correct password for
	// every user who has one. Google sign-in skips it: the identity provider
	// is the authenticator there.
	MFA SecondFactor

	// Passkeys, when set, adds sign-in with a passkey (WebAuthn).
	Passkeys *Passkeys
}

// SecondFactor is the TOTP store as the login code sees it.
type SecondFactor interface {
	Enabled(user string) bool
	// Verify checks a sign-in code (or recovery code). usedRecovery reports a
	// recovery code was used up.
	Verify(user, code string) (usedRecovery bool, err error)
	RecoveryLeft(user string) int
}

const (
	mfaCookieName = "crowsnest_mfa"
	mfaPendingTTL = 5 * time.Minute
)

type mfaPending struct {
	User string `json:"u"`
	Exp  int64  `json:"e"`
}

func userKey(username string) string {
	if len(username) > 64 {
		username = username[:64]
	}
	return "user:" + strings.ToLower(username)
}

// throttled reports whether sign-in attempts from ip, or against username ("" = not known yet), are blocked.
// Only failures count towards the limits (see failed), so signing in correctly never uses them up.
func (s *Service) throttled(ip, username string) bool {
	if s.LoginLimiter != nil && s.LoginLimiter.Blocked(ip) {
		return true
	}
	return username != "" && s.UserLimiter != nil && s.UserLimiter.Blocked(userKey(username))
}

// failed counts one wrong password or code against the address and the username.
func (s *Service) failed(ip, username string) {
	if s.LoginLimiter != nil {
		s.LoginLimiter.Hit(ip)
	}
	if username != "" && s.UserLimiter != nil {
		s.UserLimiter.Hit(userKey(username))
	}
}

// PasswordLoginDisabled reports whether password sign-in is off right now.
func (s *Service) PasswordLoginDisabled() bool {
	switch s.passwordOverride.Load() {
	case 1:
		return false
	case 2:
		return true
	}
	return s.DisablePasswordLogin
}

// SetPasswordLoginOverride applies the dashboard's choice at once; nil goes
// back to DisablePasswordLogin (config.yaml).
func (s *Service) SetPasswordLoginOverride(enabled *bool) {
	switch {
	case enabled == nil:
		s.passwordOverride.Store(0)
	case *enabled:
		s.passwordOverride.Store(1)
	default:
		s.passwordOverride.Store(2)
	}
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
	if s.PasswordLoginDisabled() {
		http.Error(w, passwordLoginDisabled, http.StatusForbidden)
		return
	}
	ip := ClientIP(r, s.TrustedProxies)
	if s.throttled(ip, "") {
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
	if s.throttled(ip, username) {
		http.Error(w, "too many login attempts, try again later", http.StatusTooManyRequests)
		return
	}

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
		s.failed(ip, username)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.upgradeHash(username, record.Hash, req.Password)

	if s.MFA != nil && s.MFA.Enabled(username) {
		token, err := s.Sessions.signPurpose("mfa-pending", mfaPending{User: username, Exp: time.Now().Add(mfaPendingTTL).Unix()})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// #nosec G124 -- HttpOnly and SameSite=Lax always; Secure follows server.secure_cookies, as for the session cookie
		http.SetCookie(w, &http.Cookie{Name: mfaCookieName, Value: token, Path: "/login/mfa", MaxAge: int(mfaPendingTTL.Seconds()),
			HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteLaxMode})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"mfa_required": true})
		return
	}

	session, err := s.newSession(w, r, username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResponse{CSRFToken: session.CSRFToken})
}

// ServeLoginMFA is the second step of a password sign-in: it checks the code
// against the user named by the pending cookie ServeLogin set, and only then
// starts the session.
func (s *Service) ServeLoginMFA(w http.ResponseWriter, r *http.Request) {
	if s.MFA == nil || s.PasswordLoginDisabled() {
		http.NotFound(w, r)
		return
	}
	ip := ClientIP(r, s.TrustedProxies)
	if s.throttled(ip, "") {
		http.Error(w, "too many login attempts, try again later", http.StatusTooManyRequests)
		return
	}
	c, err := r.Cookie(mfaCookieName)
	var p mfaPending
	if err != nil || s.Sessions.verifyPurpose("mfa-pending", c.Value, &p) != nil || time.Now().Unix() > p.Exp || p.User == "" {
		http.Error(w, "your sign-in expired: enter your password again", http.StatusUnauthorized)
		return
	}
	if s.throttled(ip, p.User) {
		http.Error(w, "too many login attempts, try again later", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	used, err := s.MFA.Verify(p.User, req.Code)
	switch {
	case err == nil:
	case errors.Is(err, mfa.ErrLocked):
		audit.Printf("%q second factor refused: locked", p.User)
		http.Error(w, "too many wrong codes, try again in a few minutes", http.StatusTooManyRequests)
		return
	default:
		audit.Printf("%q second factor refused: %v", p.User, err)
		s.failed(ip, p.User)
		http.Error(w, "that code is not right", http.StatusUnauthorized)
		return
	}
	if used {
		audit.Printf("%q signed in with a recovery code (%d left)", p.User, s.MFA.RecoveryLeft(p.User))
	}
	// #nosec G124 -- clears the pending cookie; same attributes as when it was set
	http.SetCookie(w, &http.Cookie{Name: mfaCookieName, Value: "", Path: "/login/mfa", MaxAge: -1, Expires: time.Unix(0, 0),
		HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteLaxMode})
	session, err := s.newSession(w, r, p.User)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		loginResponse
		RecoveryLeft int `json:"recovery_left"`
	}{loginResponse{CSRFToken: session.CSRFToken}, s.MFA.RecoveryLeft(p.User)})
}

// startSession signs a new session for username and sets its cookie; used by
// sign-in methods that redirect rather than answer JSON (Google).
func (s *Service) startSession(w http.ResponseWriter, r *http.Request, username string) error {
	_, err := s.newSession(w, r, username)
	return err
}

func (s *Service) newSession(w http.ResponseWriter, r *http.Request, username string) (Session, error) {
	session, err := s.Sessions.New(username)
	if err != nil {
		return Session{}, err
	}
	if reg := s.Sessions.Registry; reg != nil {
		ua := r.UserAgent()
		if len(ua) > 200 {
			ua = ua[:200]
		}
		rec := SessionRecord{ID: session.ID, User: username, Created: session.IssuedAt, LastSeen: session.IssuedAt,
			Expires: session.ExpiresAt, UserAgent: ua, IP: ClientIP(r, s.TrustedProxies)}
		if err := reg.Add(rec); err != nil {
			return Session{}, err
		}
		if s.OnSignIn != nil {
			s.OnSignIn(rec)
		}
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

// ServeLogout clears the session cookie and drops the session from the
// registry. Idempotent; doesn't require a valid session.
func (s *Service) ServeLogout(w http.ResponseWriter, r *http.Request) {
	if reg := s.Sessions.Registry; reg != nil {
		if sess, err := DecodeSessionCookie(s.Sessions, r); err == nil {
			_, _ = reg.Revoke(sess.Username, sess.ID)
		}
	}
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

// HasPassword reports whether the user has a stored password.
func (s *Service) HasPassword(username string) bool {
	if s.Store != nil {
		r, _ := s.Store.Lookup(username)
		return r.Hash != ""
	}
	return s.Users[username].Hash != ""
}

// ConfirmPassword is for a sensitive action by someone already signed in: it
// checks the password again. have is false when the user has no stored
// password (a Google-only user): there is nothing to check, and the caller
// refuses the action until one is set. A wrong answer counts against the same
// limiter as sign-in, keyed by address.
func (s *Service) ConfirmPassword(r *http.Request, username, password string) (ok, have bool, limited bool) {
	if !s.HasPassword(username) {
		return false, false, false
	}
	var record UserRecord
	if s.Store != nil {
		record, _ = s.Store.Lookup(username)
	} else {
		record = s.Users[username]
	}
	ip := ClientIP(r, s.TrustedProxies)
	if s.throttled(ip, username) {
		return false, true, true
	}
	if !VerifyPassword(record.Hash, password) {
		s.failed(ip, username)
		return false, true, false
	}
	return true, true, false
}

// upgradeHash re-hashes a correct password at the current bcrypt cost when the stored hash is weaker, so raising
// PasswordCost takes effect as people sign in. A failure only means the old hash stays.
func (s *Service) upgradeHash(username, hash, password string) {
	if s.Store == nil || !HashNeedsUpgrade(hash) {
		return
	}
	nh, err := HashPassword(password)
	if err != nil {
		return
	}
	if err := SetUserHash(s.Store.Path(), username, nh); err != nil {
		log.Printf("auth: could not upgrade %s's password hash: %v", username, err)
		return
	}
	if _, err := s.Store.Reload(); err != nil {
		log.Printf("auth: reload users after a hash upgrade: %v", err)
	}
}
