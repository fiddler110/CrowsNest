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
	Disable(id string) error
	Policy() (managed.PolicyState, error)
	SetPolicy(managed.PolicyDoc) error
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
	data := dashboardData{Page: "games", Username: session.Username, IsAdmin: true, CSRFToken: session.CSRFToken}
	render(w, a.Templates.Games, data, "games page")
}

// handleSettingsPage serves the Settings page (admins only).
func (a *App) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	session, _ := auth.FromContext(r.Context())
	if a.Auth.Sessions.RoleFor(session.Username) != auth.RoleAdmin {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	data := dashboardData{Page: "settings", Username: session.Username, IsAdmin: true, CSRFToken: session.CSRFToken}
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
	a.record(r, req.ID, "enabled from module "+req.Module)
	a.pokeGame(req.ID) // re-observe; an id the hub lacks prompts a registry reconcile
	writeJSON(w, http.StatusAccepted, map[string]string{"id": req.ID, "state": managed.StateInstalling})
}

func (a *App) handleManagedDisable(w http.ResponseWriter, r *http.Request) {
	if !a.managedOn(w) {
		return
	}
	id := r.PathValue("id")
	if err := a.Managed.Disable(id); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	a.record(r, id, "disabled")
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
