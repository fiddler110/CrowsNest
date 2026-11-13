package web

import (
	"net/http"
	"strings"

	"github.com/fiddler110/crowsnest/internal/auth"
)

// mfaExempt are the paths an admin may use before setting up an authenticator app: their Account page and what it
// calls, sign-out, and the static files the page needs.
func mfaExempt(path string) bool {
	return path == "/account" || path == "/logout" || path == "/healthz" || strings.HasPrefix(path, "/api/account/") ||
		strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/login")
}

// MFAGate wraps next so that, while Settings, "Require admins to use an authenticator app" is on, an admin who signs
// in with a password and has no authenticator yet can reach only their Account page until they set one up. Pages
// redirect there; API calls get a 403 that says why. Admins who sign in through Google or another provider are not
// asked: their provider does the second factor.
func (a *App) MFAGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.mfaEnrolmentNeeded(r) && !mfaExempt(r.URL.Path) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "set up an authenticator app on your Account page first: admins are required to use one", http.StatusForbidden)
				return
			}
			http.Redirect(w, r, "/account#totp", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) mfaEnrolmentNeeded(r *http.Request) bool {
	if a.Settings == nil || a.MFA == nil || !a.Settings.Get().RequireAdminMFA {
		return false
	}
	session, err := auth.DecodeSessionCookie(a.Auth.Sessions, r)
	if err != nil {
		return false // not signed in: the normal sign-in flow applies
	}
	user := session.Username
	return a.Auth.Sessions.RoleFor(user) == auth.RoleAdmin && a.Auth.HasPassword(user) && !a.MFA.Enabled(user) &&
		(a.Auth.Passkeys == nil || a.Auth.Passkeys.Store.Count(user) == 0)
}
