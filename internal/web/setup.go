package web

import (
	"encoding/json"
	"errors"
	"github.com/fiddler110/crowsnest/internal/audit"
	"log"
	"net/http"
	"strings"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/history"
)

const maxSetupBodyBytes = 4096

type setupPage struct {
	PasswordLogin bool // a password is asked for (otherwise a Google email is)
	Google        bool // a Google email may be linked
}

type setupRequest struct {
	Code        string `json:"code"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	GoogleEmail string `json:"google_email"`
}

// setupNeeded reports whether first-run setup is open: it is wired up and the
// users file has no users.
func (a *App) setupNeeded() bool { return a.Setup != nil && a.Setup.Needed() }

// handleSetupPage serves the first-run page, or sends the visitor to sign in
// once a user exists.
func (a *App) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	if !a.setupNeeded() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if code, created, err := a.Setup.Code(); err != nil {
		log.Printf("setup: could not make a setup code: %v", err)
	} else if created {
		log.Printf("setup: no users yet. Open /setup and enter the setup code %s (also saved in %s)", code, a.Setup.CodeFile)
	}
	render(w, a.Templates.Setup, setupPage{PasswordLogin: !a.Auth.PasswordLoginDisabled(), Google: a.Google.Active()}, "setup page")
}

// handleSetup creates the first admin. It is rate limited per client address
// like sign-in, and answers every failure of the code the same way.
func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !a.setupNeeded() {
		http.Error(w, "setup is already done", http.StatusConflict)
		return
	}
	ip := auth.ClientIP(r, a.Auth.TrustedProxies)
	if a.Auth.LoginLimiter != nil && !a.Auth.LoginLimiter.Allow(ip) {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSetupBodyBytes)
	var req setupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Username))
	if err := auth.ValidateUsername(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hash, email := "", ""
	if !a.Auth.PasswordLoginDisabled() {
		if err := checkPassword(req.Password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h, err := auth.HashPassword(req.Password)
		if err != nil {
			http.Error(w, "could not save the account", http.StatusInternalServerError)
			return
		}
		hash = h
	}
	if strings.TrimSpace(req.GoogleEmail) != "" || a.Auth.PasswordLoginDisabled() {
		e, err := a.checkGoogleEmail(req.GoogleEmail, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		email = e
	}
	switch err := a.Setup.Complete(req.Code, name, hash, email); {
	case err == nil:
	case errors.Is(err, auth.ErrBadSetupCode):
		log.Printf("setup: wrong setup code from %s", ip)
		http.Error(w, "that setup code is wrong", http.StatusForbidden)
		return
	case errors.Is(err, auth.ErrSetupDone):
		http.Error(w, "setup is already done", http.StatusConflict)
		return
	default:
		log.Printf("setup: %v", err)
		http.Error(w, "could not save the account; see the CrowsNest log", http.StatusInternalServerError)
		return
	}
	audit.Printf("first admin %q created from %s", name, ip)
	if a.History != nil {
		a.History.Record(history.KindUsers, "", name, "first-run setup created the admin")
	}
	w.WriteHeader(http.StatusNoContent)
}
