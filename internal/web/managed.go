package web

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

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
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id, "state": managed.StateInstalling})
}
