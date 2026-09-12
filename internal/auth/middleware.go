package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

type contextKey int

const (
	sessionContextKey contextKey = iota
	nonceContextKey
)

// FromContext returns the session RequireSession attached to this request,
// if any.
func FromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionContextKey).(Session)
	return s, ok
}

// WithSession attaches session to ctx the same way RequireSession does. For
// callers that need their own request-handling wrapper around session
// verification (e.g. one that redirects to a login page instead of
// returning 401 JSON), pair this with DecodeSessionCookie.
func WithSession(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, s)
}

// DecodeSessionCookie reads and verifies the session cookie on r, if any.
func DecodeSessionCookie(sessions *SessionManager, r *http.Request) (Session, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return Session{}, ErrInvalidSession
	}
	return sessions.Decode(cookie.Value)
}

// RequireSession rejects requests without a valid, unexpired session
// cookie, and attaches the decoded Session to the request context for
// downstream handlers (and RequireCSRF). Responds 401 on failure — meant
// for the JSON API; HTML routes that should redirect to a login page
// instead build their own wrapper on DecodeSessionCookie/WithSession.
func RequireSession(sessions *SessionManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := DecodeSessionCookie(sessions, r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithSession(r.Context(), session)))
	})
}

// RequireCSRF checks the X-CSRF-Token header against the token embedded in
// the caller's session. Must run behind RequireSession (which populates the
// context). Intended for state-changing requests only — GETs don't need it.
func RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := FromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		got := r.Header.Get("X-CSRF-Token")
		if got == "" || !hmac.Equal([]byte(got), []byte(session.CSRFToken)) {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NonceFromContext returns the CSP nonce SecurityHeaders attached to this
// request, if any. Phase 5's templates use it to emit matching
// <script nonce="..."> / <style nonce="..."> attributes.
func NonceFromContext(ctx context.Context) (string, bool) {
	n, ok := ctx.Value(nonceContextKey).(string)
	return n, ok
}

// SecurityHeaders sets a baseline set of hardening headers, including a CSP
// with a per-request nonce. hsts should be true when the deployment sits
// behind a TLS-terminating reverse proxy (config.Server.SecureCookies) —
// sending Strict-Transport-Security over plain HTTP would be misleading.
func SecurityHeaders(hsts bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonceBytes := make([]byte, 16)
		nonce := ""
		if _, err := rand.Read(nonceBytes); err == nil {
			nonce = base64.StdEncoding.EncodeToString(nonceBytes)
		}

		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		if hsts {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}

		csp := "default-src 'self'"
		if nonce != "" {
			csp += "; script-src 'self' 'nonce-" + nonce + "'; style-src 'self' 'nonce-" + nonce + "'"
		} else {
			csp += "; script-src 'self'; style-src 'self'"
		}
		w.Header().Set("Content-Security-Policy", csp)

		if nonce != "" {
			r = r.WithContext(context.WithValue(r.Context(), nonceContextKey, nonce))
		}
		next.ServeHTTP(w, r)
	})
}
