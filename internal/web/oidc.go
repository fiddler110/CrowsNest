package web

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
)

// oidcView is one provider as the settings page sees it: never the secret.
type oidcView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Issuer      string `json:"issuer"`
	ClientID    string `json:"client_id"`
	HasSecret   bool   `json:"has_secret"`
	RedirectURL string `json:"redirect_url"`
	Enabled     bool   `json:"enabled"`
}

func (a *App) oidcViews() []oidcView {
	out := []oidcView{}
	for _, p := range a.OIDC.Store.List() {
		out = append(out, oidcView{p.ID, p.Name, p.Issuer, p.ClientID, p.ClientSecret != "", p.RedirectURL, p.Enabled})
	}
	return out
}

func (a *App) oidcOn(w http.ResponseWriter, r *http.Request) bool {
	if a.OIDC == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (a *App) handleListOIDC(w http.ResponseWriter, r *http.Request) {
	if !a.oidcOn(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": a.oidcViews()})
}

func (a *App) whenOIDC(serve func(*auth.OIDCLogin, http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.OIDC == nil {
			http.NotFound(w, r)
			return
		}
		serve(a.OIDC, w, r, r.PathValue("id"))
	}
}

type oidcBody struct {
	Name         string  `json:"name"`
	Issuer       string  `json:"issuer"`
	ClientID     string  `json:"client_id"`
	ClientSecret *string `json:"client_secret"` // nil or "" keeps the saved one
	RedirectURL  string  `json:"redirect_url"`
	Enabled      bool    `json:"enabled"`
	Password     string  `json:"password"`
	Confirm      bool    `json:"confirm"`
}

// lockoutCheck answers 409 (and returns false) when turning OIDC provider
// changes would leave an admin unable to sign in, or, without confirm, other
// people. after says whether any OIDC provider stays on.
func (a *App) oidcLockoutCheck(w http.ResponseWriter, r *http.Request, afterOIDC, confirm bool) bool {
	var env auth.GoogleUsers
	if a.Google != nil {
		env = a.Google.Users
	}
	pw, g := !a.Auth.PasswordLoginDisabled(), a.Google.Active()
	reach := auth.Reachability(a.Auth.Store.Snapshot(), env,
		auth.SignInMethods{Password: pw, Google: g, OIDC: a.OIDC.Store.AnyEnabled()},
		auth.SignInMethods{Password: pw, Google: g, OIDC: afterOIDC})
	if reach.AdminsLeft == 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"refused": true, "locked_out": reach.Locked,
			"message": "No admin could sign in after this change. Turn password sign-in back on, or link an admin to another sign-in method first."})
		return false
	}
	if len(reach.Locked) > 0 && !confirm {
		writeJSON(w, http.StatusConflict, map[string]any{"needs_confirm": true, "locked_out": reach.Locked, "you_locked_out": slices.Contains(reach.Locked, actor(r)),
			"message": "These people could only sign in through this provider and would be locked out."})
		return false
	}
	return true
}

func (a *App) handlePutOIDC(w http.ResponseWriter, r *http.Request) {
	if !a.oidcOn(w, r) {
		return
	}
	id := r.PathValue("id")
	var b oidcBody
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}
	prev, existed := a.OIDC.Store.Get(id)
	p := auth.OIDCProvider{ID: id, Name: strings.TrimSpace(b.Name), Issuer: strings.TrimRight(strings.TrimSpace(b.Issuer), "/"),
		ClientID: strings.TrimSpace(b.ClientID), ClientSecret: prev.ClientSecret, RedirectURL: strings.TrimSpace(b.RedirectURL), Enabled: b.Enabled}
	if b.ClientSecret != nil && strings.TrimSpace(*b.ClientSecret) != "" {
		p.ClientSecret = strings.TrimSpace(*b.ClientSecret)
	}
	if existed && prev.Issuer != p.Issuer && p.ClientSecret == prev.ClientSecret {
		http.Error(w, "you changed the issuer: enter the client secret for the new provider too", http.StatusBadRequest)
		return
	}
	if err := p.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	authURL, tokenURL, err := auth.Discover(ctx, nil, p.Issuer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.AuthURL, p.TokenURL = authURL, tokenURL
	if existed && prev.Enabled && !p.Enabled {
		others := false
		for _, o := range a.OIDC.Store.List() {
			others = others || (o.ID != id && o.Enabled)
		}
		if !a.oidcLockoutCheck(w, r, others, b.Confirm) {
			return
		}
	}
	if !a.confirmAdmin(w, r, b.Password) {
		return
	}
	if err := a.OIDC.Store.Put(p); err != nil {
		http.Error(w, "could not save: "+err.Error(), http.StatusBadRequest)
		return
	}
	state := "off"
	if p.Enabled {
		state = "on"
	}
	detail := "sign-in provider " + p.Name + " (" + hostOf(p.Issuer) + ") " + state
	if b.ClientSecret != nil && strings.TrimSpace(*b.ClientSecret) != "" {
		detail += ", secret replaced"
	}
	a.recordAuth(r, detail)
	writeJSON(w, http.StatusOK, map[string]any{"providers": a.oidcViews()})
}

func (a *App) handleDeleteOIDC(w http.ResponseWriter, r *http.Request) {
	if !a.oidcOn(w, r) {
		return
	}
	id := r.PathValue("id")
	var b struct {
		Password string `json:"password"`
		Confirm  bool   `json:"confirm"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	_ = json.NewDecoder(r.Body).Decode(&b)
	p, ok := a.OIDC.Store.Get(id)
	if !ok {
		http.Error(w, "no such provider", http.StatusNotFound)
		return
	}
	if p.Enabled {
		others := false
		for _, o := range a.OIDC.Store.List() {
			others = others || (o.ID != id && o.Enabled)
		}
		if !a.oidcLockoutCheck(w, r, others, b.Confirm) {
			return
		}
	}
	if !a.confirmAdmin(w, r, b.Password) {
		return
	}
	if err := a.OIDC.Store.Delete(id); err != nil {
		http.Error(w, "could not remove: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.recordAuth(r, "removed sign-in provider "+p.Name)
	writeJSON(w, http.StatusOK, map[string]any{"providers": a.oidcViews()})
}

// oidcButtons are the login page's "Sign in with ..." links.
func (a *App) oidcButtons() []oidcButton {
	if a.OIDC == nil {
		return nil
	}
	var out []oidcButton
	for _, p := range a.OIDC.Store.List() {
		if p.Enabled {
			out = append(out, oidcButton{Name: p.Name, URL: p.StartURL()})
		}
	}
	return out
}

type oidcButton struct{ Name, URL string }
