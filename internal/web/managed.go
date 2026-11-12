package web

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/history"
	"github.com/fiddler110/crowsnest/internal/managed"
)

// ManagedGames is what the dashboard's Games API needs from the managed-game
// manager (internal/managed).
type ManagedGames interface {
	Catalogue() []managed.ModuleInfo
	List() []managed.Info
	Preview(managed.Request) (*managed.Plan, error)
	Enable(managed.Request) error
	Update(managed.Request) error
	Refresh(id string) error
	Rollback(id string) error
	Disable(id string, o managed.DisableOptions) error
	Policy() (managed.PolicyState, error)
	SetPolicy(managed.PolicyDoc) error
	SetAllowed(id string, on bool) error
}

const maxManagedBody = 32 << 10

func (a *App) managedOn(w http.ResponseWriter) bool {
	if a.Managed == nil {
		http.Error(w, "enabling games from the dashboard is not configured (managed.dir in config.yaml)", http.StatusNotFound)
		return false
	}
	return true
}

func (a *App) handleManagedModules(w http.ResponseWriter, r *http.Request) {
	if !a.managedOn(w) {
		return
	}
	writeJSON(w, http.StatusOK, a.Managed.Catalogue())
}

func (a *App) handleManagedList(w http.ResponseWriter, r *http.Request) {
	if !a.managedOn(w) {
		return
	}
	writeJSON(w, http.StatusOK, a.Managed.List())
}

// handleGamesPage serves the Games page (admins only; players go back to the dashboard).
func (a *App) handleGamesPage(w http.ResponseWriter, r *http.Request) {
	session, _ := auth.FromContext(r.Context())
	if a.Auth.Sessions.RoleFor(session.Username) != auth.RoleAdmin {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	data := dashboardData{Page: "games", Username: session.Username, DisplayName: a.Profiles.DisplayName(session.Username), IsAdmin: true, CSRFToken: session.CSRFToken, NeedsPassword: !a.Auth.HasPassword(session.Username)}
	render(w, a.Templates.Games, data, "games page")
}

// handleSettingsPage serves the Settings page (admins only).
func (a *App) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	session, _ := auth.FromContext(r.Context())
	if a.Auth.Sessions.RoleFor(session.Username) != auth.RoleAdmin {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	data := dashboardData{Page: "settings", Username: session.Username, DisplayName: a.Profiles.DisplayName(session.Username), IsAdmin: true, CSRFToken: session.CSRFToken, NeedsPassword: !a.Auth.HasPassword(session.Username)}
	render(w, a.Templates.Settings, data, "settings page")
}

// handleManagedConfigured lists the games that come from config.yaml (everything
// on the dashboard that was not enabled from it), read-only, so the Games dialog
// shows the whole fleet in one place.
func (a *App) handleManagedConfigured(w http.ResponseWriter, r *http.Request) {
	managedIDs := map[string]bool{}
	if a.Managed != nil {
		for _, g := range a.Managed.List() {
			managedIDs[g.ID] = true
		}
	}
	type row struct {
		ID             string `json:"id"`
		DisplayName    string `json:"display_name"`
		ConnectAddress string `json:"connect_address,omitempty"`
		Container      string `json:"container,omitempty"`
	}
	out := []row{}
	for _, d := range a.Registry.All() {
		if managedIDs[d.ID] {
			continue
		}
		out = append(out, row{ID: d.ID, DisplayName: d.DisplayName, ConnectAddress: d.ConnectAddress, Container: d.ContainerName})
	}
	writeJSON(w, http.StatusOK, out)
}

func readManagedRequest(w http.ResponseWriter, r *http.Request) (managed.Request, bool) {
	var req managed.Request
	r.Body = http.MaxBytesReader(w, r.Body, maxManagedBody)
	raw, err := io.ReadAll(r.Body)
	if err == nil {
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		err = dec.Decode(&req)
	}
	if err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return req, false
	}
	return req, true
}

func (a *App) handleManagedPreview(w http.ResponseWriter, r *http.Request) {
	if !a.managedOn(w) {
		return
	}
	req, ok := readManagedRequest(w, r)
	if !ok {
		return
	}
	plan, err := a.Managed.Preview(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (a *App) handleManagedEnable(w http.ResponseWriter, r *http.Request) {
	if !a.managedOn(w) {
		return
	}
	req, ok := readManagedRequest(w, r)
	if !ok {
		return
	}
	if err := a.Managed.Enable(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	detail := "enabled from module " + req.Module
	if req.CopyFrom != "" {
		detail += ", as a copy of " + req.CopyFrom
	}
	a.record(r, req.ID, detail)
	a.pokeGame(req.ID) // re-observe; an id the hub lacks prompts a registry reconcile
	writeJSON(w, http.StatusAccepted, map[string]string{"id": req.ID, "state": managed.StateInstalling})
}

// handleManagedDisable removes a stopped game. An optional JSON body can also
// ask for its data folders and/or its backups to be deleted; that is
// irreversible, so it needs the game's id typed out and the admin's password.
func (a *App) handleManagedDisable(w http.ResponseWriter, r *http.Request) {
	if !a.managedOn(w) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		DeleteData    bool   `json:"delete_data"`
		DeleteBackups bool   `json:"delete_backups"`
		ConfirmID     string `json:"confirm_id"`
		Password      string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if raw, err := io.ReadAll(r.Body); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	} else if len(strings.TrimSpace(string(raw))) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	opts := managed.DisableOptions{Data: body.DeleteData, Backups: body.DeleteBackups}
	if opts.Data || opts.Backups {
		if body.ConfirmID != id {
			http.Error(w, "type the game's id to confirm deleting its data", http.StatusBadRequest)
			return
		}
		session, _ := auth.FromContext(r.Context())
		ok, have, limited := a.Auth.ConfirmPassword(r, session.Username, body.Password)
		switch {
		case !have:
			http.Error(w, "set a password for your account first (Settings, Users): deleting data asks for it, even if you sign in with Google", http.StatusForbidden)
			return
		case limited:
			http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
			return
		case !ok:
			a.record(r, id, "refused to delete game data: wrong password")
			http.Error(w, "that password is not right", http.StatusForbidden)
			return
		}
	}
	if err := a.Managed.Disable(id, opts); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	detail := "disabled"
	switch {
	case opts.Data && opts.Backups:
		detail = "disabled; its data folders and its backups were deleted"
	case opts.Data:
		detail = "disabled; its data folders were deleted (backups kept)"
	case opts.Backups:
		detail = "disabled; its backups were deleted (data folders kept)"
	}
	a.record(r, id, detail)
	a.pokeGame(id) // re-observe; an id the hub lacks prompts a registry reconcile
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) record(r *http.Request, game, detail string) {
	if a.History != nil {
		a.History.Record(history.KindGames, game, actor(r), detail)
	}
}

func (a *App) handleManagedUpdate(w http.ResponseWriter, r *http.Request) {
	if !a.managedOn(w) {
		return
	}
	req, ok := readManagedRequest(w, r)
	if !ok {
		return
	}
	if req.ID != "" && req.ID != r.PathValue("id") {
		http.Error(w, "id in the body does not match the URL", http.StatusBadRequest)
		return
	}
	req.ID = r.PathValue("id")
	if err := a.Managed.Update(req); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	a.record(r, req.ID, "changed settings")
	a.pokeGame(req.ID) // re-observe; an id the hub lacks prompts a registry reconcile
	writeJSON(w, http.StatusAccepted, map[string]string{"id": req.ID, "state": managed.StateInstalling})
}

func (a *App) handleManagedRefresh(w http.ResponseWriter, r *http.Request) {
	if !a.managedOn(w) {
		return
	}
	id := r.PathValue("id")
	if err := a.Managed.Refresh(id); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	a.record(r, id, "updating image")
	a.pokeGame(id) // re-observe; an id the hub lacks prompts a registry reconcile
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id, "state": managed.StateInstalling})
}

// handleManagedRollback recreates a stopped game on its previous image digest.
// Every refusal (no previous image, running, starting or stopping) is a 409.
func (a *App) handleManagedRollback(w http.ResponseWriter, r *http.Request) {
	if !a.managedOn(w) {
		return
	}
	id := r.PathValue("id")
	if err := a.Managed.Rollback(id); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	a.record(r, id, "rolling back to the previous image")
	a.pokeGame(id) // re-observe; an id the hub lacks prompts a registry reconcile
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id, "state": managed.StateInstalling})
}

func (a *App) handleManagedPolicy(w http.ResponseWriter, r *http.Request) {
	if !a.managedOn(w) {
		return
	}
	st, err := a.Managed.Policy()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *App) handleManagedSetPolicy(w http.ResponseWriter, r *http.Request) {
	if !a.managedOn(w) {
		return
	}
	var doc managed.PolicyDoc
	r.Body = http.MaxBytesReader(w, r.Body, maxManagedBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.Managed.SetPolicy(doc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.record(r, "policy", "changed the policy")
	st, _ := a.Managed.Policy()
	writeJSON(w, http.StatusOK, st)
}

// handleManagedAllow switches a bundled module on or off. It widens what the
// guard accepts (that module's ports), so the admin proves who they are again
// with their password, and the change goes in the history.
func (a *App) handleManagedAllow(w http.ResponseWriter, r *http.Request) {
	if !a.managedOn(w) {
		return
	}
	var body struct {
		Allowed  bool   `json:"allowed"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}
	session, _ := auth.FromContext(r.Context())
	// Turning a module off only narrows things; asking for the password again is for widening.
	if body.Allowed {
		ok, have, limited := a.Auth.ConfirmPassword(r, session.Username, body.Password)
		switch {
		case !have:
			http.Error(w, "set a password for your account first (Settings, Users): widening the guard asks for it, even if you sign in with Google", http.StatusForbidden)
			return
		case limited:
			http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
			return
		case !ok:
			a.record(r, r.PathValue("id"), "refused to allow a module: wrong password")
			http.Error(w, "that password is not right", http.StatusForbidden)
			return
		}
	}
	id := r.PathValue("id")
	if err := a.Managed.SetAllowed(id, body.Allowed); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	verb := "turned off"
	if body.Allowed {
		verb = "allowed"
	}
	a.record(r, id, verb+" the "+id+" module (its ports in the policy)")
	w.WriteHeader(http.StatusNoContent)
}
