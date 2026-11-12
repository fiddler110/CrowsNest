package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/history"
)

// googleView is GET /api/auth/google. The client secret is never sent back:
// only whether one is set.
type googleView struct {
	Source      string `json:"source"` // dashboard, environment or none
	Enabled     bool   `json:"enabled"`
	ClientID    string `json:"client_id"`
	HasSecret   bool   `json:"has_secret"`
	RedirectURL string `json:"redirect_url"`
	// Editable is false when the dashboard can't store settings (no store).
	Editable      bool   `json:"editable"`
	PasswordLogin bool   `json:"password_login"`
	CallbackPath  string `json:"callback_path"`
}

func (a *App) googleOn(w http.ResponseWriter, r *http.Request) bool {
	if a.GoogleConf == nil || a.Google == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (a *App) googleView() googleView {
	v, src := a.GoogleConf.Effective()
	return googleView{
		Source: src, Enabled: v.Enabled && a.Google.Active(), ClientID: v.ClientID, HasSecret: v.ClientSecret != "",
		RedirectURL: v.RedirectURL, Editable: true, PasswordLogin: !a.Auth.PasswordLoginDisabled(),
		CallbackPath: auth.GoogleCallbackPath,
	}
}

func (a *App) handleGetGoogle(w http.ResponseWriter, r *http.Request) {
	if !a.googleOn(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, a.googleView())
}

type googleBody struct {
	Enabled      bool    `json:"enabled"`
	ClientID     string  `json:"client_id"`
	ClientSecret *string `json:"client_secret"` // nil or "" keeps the saved one
	RedirectURL  string  `json:"redirect_url"`
	Password     string  `json:"password"`
}

// confirmAdmin asks for the admin's own password again before the sign-in
// setup changes: whoever controls it controls how everyone gets in.
func (a *App) confirmAdmin(w http.ResponseWriter, r *http.Request, password string) bool {
	ok, have, limited := a.Auth.ConfirmPassword(r, actor(r), password)
	switch {
	case !have:
		http.Error(w, "set a password for your account first (Settings, Users): changing how people sign in asks for it, even if you sign in with Google", http.StatusForbidden)
	case limited:
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
	case !ok:
		a.recordAuth(r, "refused a sign-in change: wrong password")
		http.Error(w, "that password is not right", http.StatusForbidden)
	default:
		return true
	}
	return false
}

func (a *App) recordAuth(r *http.Request, detail string) {
	if a.History != nil {
		a.History.Record(history.KindSettings, "", actor(r), detail)
	}
}

func (a *App) handlePutGoogle(w http.ResponseWriter, r *http.Request) {
	if !a.googleOn(w, r) {
		return
	}
	var b googleBody
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}
	cur, _ := a.GoogleConf.Effective()
	next := auth.GoogleSettings{
		Enabled:      b.Enabled,
		ClientID:     strings.TrimSpace(b.ClientID),
		ClientSecret: cur.ClientSecret,
		RedirectURL:  strings.TrimSpace(b.RedirectURL),
	}
	if b.ClientSecret != nil && strings.TrimSpace(*b.ClientSecret) != "" {
		next.ClientSecret = strings.TrimSpace(*b.ClientSecret)
	}
	if err := next.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !next.Enabled && a.Auth.PasswordLoginDisabled() {
		http.Error(w, "password sign-in is off in config.yaml, so turning Google off would lock everyone out", http.StatusConflict)
		return
	}
	if !a.confirmAdmin(w, r, b.Password) {
		return
	}
	if err := a.GoogleConf.Save(next); err != nil {
		http.Error(w, "could not save: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.GoogleConf.Apply(a.Google)
	state := "off"
	if next.Enabled {
		state = "on"
	}
	detail := "Google sign-in " + state + ", client " + next.ClientID + ", redirect " + hostOf(next.RedirectURL)
	if b.ClientSecret != nil && strings.TrimSpace(*b.ClientSecret) != "" {
		detail += ", secret replaced"
	}
	a.recordAuth(r, detail)
	writeJSON(w, http.StatusOK, a.googleView())
}

func (a *App) handleDeleteGoogle(w http.ResponseWriter, r *http.Request) {
	if !a.googleOn(w, r) {
		return
	}
	var b struct {
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	_ = json.NewDecoder(r.Body).Decode(&b)
	if fb := a.GoogleConf.Fallback; a.Auth.PasswordLoginDisabled() && !fb.Enabled {
		http.Error(w, "password sign-in is off in config.yaml and nothing else would turn Google on, so this would lock everyone out", http.StatusConflict)
		return
	}
	if !a.confirmAdmin(w, r, b.Password) {
		return
	}
	if err := a.GoogleConf.Clear(); err != nil {
		http.Error(w, "could not remove: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.GoogleConf.Apply(a.Google)
	a.recordAuth(r, "removed the Google sign-in settings saved here (config.yaml and environment apply again)")
	writeJSON(w, http.StatusOK, a.googleView())
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// passwordLoginView is GET /api/auth/password-login.
type passwordLoginView struct {
	Enabled bool `json:"enabled"`
	// Source is "dashboard" when a choice was saved here, else "config".
	Source string `json:"source"`
}

func (a *App) passwordLoginView() passwordLoginView {
	src := "config"
	if a.AuthPrefs != nil && a.AuthPrefs.PasswordLogin() != nil {
		src = "dashboard"
	}
	return passwordLoginView{Enabled: !a.Auth.PasswordLoginDisabled(), Source: src}
}

func (a *App) handleGetPasswordLogin(w http.ResponseWriter, r *http.Request) {
	if a.AuthPrefs == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, a.passwordLoginView())
}

type passwordLoginBody struct {
	Enabled  bool   `json:"enabled"`
	Password string `json:"password"`
	// Confirm acknowledges the lock-out warning for the same request.
	Confirm bool `json:"confirm"`
}

// handlePutPasswordLogin turns password sign-in on or off. Turning it off
// works out who could no longer sign in and, if that is anyone, answers 409
// with the list until the same request is sent again with confirm set. If no
// admin could sign in afterwards it is refused outright.
func (a *App) handlePutPasswordLogin(w http.ResponseWriter, r *http.Request) {
	if a.AuthPrefs == nil {
		http.NotFound(w, r)
		return
	}
	var b passwordLoginBody
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}
	nowOn := !a.Auth.PasswordLoginDisabled()
	if b.Enabled == nowOn {
		writeJSON(w, http.StatusOK, a.passwordLoginView())
		return
	}
	if !b.Enabled {
		var env auth.GoogleUsers
		if a.Google != nil {
			env = a.Google.Users
		}
		googleOn, oidcOn := a.Google.Active(), a.OIDC != nil && a.OIDC.Store.AnyEnabled()
		reach := auth.Reachability(a.Auth.Store.Snapshot(), env, auth.SignInMethods{Password: true, Google: googleOn, OIDC: oidcOn}, auth.SignInMethods{Google: googleOn, OIDC: oidcOn})
		if reach.AdminsLeft == 0 {
			writeJSON(w, http.StatusConflict, map[string]any{
				"refused": true, "locked_out": reach.Locked,
				"message": "No admin could sign in once passwords are off: none is linked to a Google account or an OIDC provider that is switched on. Set one up and link an admin first, under Settings, Sign-in and Users.",
			})
			return
		}
		if len(reach.Locked) > 0 && !b.Confirm {
			writeJSON(w, http.StatusConflict, map[string]any{
				"needs_confirm": true, "locked_out": reach.Locked, "you_locked_out": slices.Contains(reach.Locked, actor(r)),
				"message": "These people can only sign in with a password and would be locked out. Everyone signed in with a password is signed out at once.",
			})
			return
		}
	}
	if !a.confirmAdmin(w, r, b.Password) {
		return
	}
	if err := a.AuthPrefs.SetPasswordLogin(&b.Enabled); err != nil {
		http.Error(w, "could not save: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.Auth.SetPasswordLoginOverride(&b.Enabled)
	state := "off"
	if b.Enabled {
		state = "on"
	}
	a.recordAuth(r, "password sign-in turned "+state)
	writeJSON(w, http.StatusOK, a.passwordLoginView())
}
