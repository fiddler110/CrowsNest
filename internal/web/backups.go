package web

import (
	"encoding/json"
	"errors"
	"github.com/fiddler110/crowsnest/internal/audit"
	"log"
	"net/http"
	"strings"

	"github.com/fiddler110/crowsnest/internal/backup"
	"github.com/fiddler110/crowsnest/internal/restore"
)

// handleBackup starts a backup of one game in the background.
func (a *App) handleBackup(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	if a.Backups == nil {
		http.Error(w, "backups are not configured", http.StatusNotFound)
		return
	}
	switch err := a.Backups.Request(r.Context(), d, actor(r)); {
	case err == nil:
		audit.Printf("%s requested backup of %s", actor(r), d.ID)
		w.WriteHeader(http.StatusAccepted)
	case errors.Is(err, backup.ErrNotConfigured):
		http.Error(w, "this game has no backup configured", http.StatusNotFound)
	case errors.Is(err, backup.ErrNotRunning), errors.Is(err, backup.ErrBusy), errors.Is(err, backup.ErrRootUnavailable):
		http.Error(w, strings.TrimPrefix(err.Error(), "backup: "), http.StatusConflict)
	default:
		audit.Printf("%s backup %s failed: %v", actor(r), d.ID, err)
		http.Error(w, publicError(err), http.StatusBadGateway)
	}
}

// handleRestore starts restoring one backup file of a game in the background.
// The body names the file: {"file": "<name>"}. The game is stopped (and started
// again if it was running), so the caller has already confirmed it.
func (a *App) handleRestore(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	if a.Restore == nil {
		http.Error(w, "restoring is not configured", http.StatusNotFound)
		return
	}
	var body struct {
		File     string `json:"file"`
		Password string `json:"password"`
		// WithoutBackup accepts losing the current world of a stopped game, which
		// cannot be backed up first.
		WithoutBackup bool `json:"without_backup"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Overwriting a world is as destructive as deleting it: ask for the password again.
	if !a.stepUp(w, r, body.Password, "restore "+d.ID) {
		return
	}
	switch err := a.Restore.Request(r.Context(), d, body.File, actor(r), body.WithoutBackup); {
	case err == nil:
		w.WriteHeader(http.StatusAccepted)
	case errors.Is(err, restore.ErrNoSafetyBackup):
		http.Error(w, err.Error(), http.StatusPreconditionRequired)
	case errors.Is(err, restore.ErrNotConfigured):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, restore.ErrBadFile):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, restore.ErrBusy), errors.Is(err, restore.ErrWouldPrune), errors.Is(err, backup.ErrRootUnavailable):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		log.Printf("web: restore %s: %v", d.ID, err)
		http.Error(w, publicError(err), http.StatusBadGateway)
	}
}

// handleBackupsHealth reports the shared backups folder's latest check: whether
// it is usable, free space, problems, and folders no game uses (admin only).
func (a *App) handleBackupsHealth(w http.ResponseWriter, r *http.Request) {
	if a.Backups == nil || a.Backups.Root == nil {
		http.Error(w, "no shared backups folder is configured", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		backup.Health
		Offsite backup.OffsiteStatus `json:"offsite"`
	}{a.Backups.Health(), a.Backups.Offsite()})
}

// handleBackups lists a game's backup files, newest first.
func (a *App) handleBackups(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	if a.Backups == nil {
		http.Error(w, "backups are not configured", http.StatusNotFound)
		return
	}
	canRestore := a.Restore != nil && d.Backup != nil && d.Backup.CanRestore
	busy := a.Backups.Running(d.ID) || (a.Restore != nil && a.Restore.Running(d.ID))
	files, err := a.Backups.List(r.Context(), d)
	switch {
	case errors.Is(err, backup.ErrNotConfigured):
		writeJSON(w, http.StatusOK, map[string]any{"files": []backup.File{}, "running": busy})
	case err != nil:
		// Usually just "the container isn't running".
		writeJSON(w, http.StatusOK, map[string]any{"files": []backup.File{}, "running": busy, "unavailable": true})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"files": files, "running": busy, "restorable": canRestore,
			"restoring": a.Restore != nil && a.Restore.Running(d.ID)})
	}
}

type backupOverviewGame struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Count       int          `json:"count"`
	Latest      *backup.File `json:"latest,omitempty"`
	Unavailable bool         `json:"unavailable,omitempty"` // the list could not be read (the game is stopped and keeps its backups inside)
	Restorable  bool         `json:"restorable"`
	Running     bool         `json:"running"`
}

// handleBackupsOverview is the Backups page's data: for every game with a backup set up, how many backups there
// are and the newest one, beside the shared folder's health (admin only). A game whose backups live inside its own
// container can only be listed while it runs.
func (a *App) handleBackupsOverview(w http.ResponseWriter, r *http.Request) {
	if a.Backups == nil {
		http.Error(w, "backups are not configured", http.StatusNotFound)
		return
	}
	out := struct {
		Games   []backupOverviewGame  `json:"games"`
		Health  *backup.Health        `json:"health,omitempty"`
		Offsite *backup.OffsiteStatus `json:"offsite,omitempty"`
	}{Games: []backupOverviewGame{}}
	if a.Backups.Root != nil {
		h, o := a.Backups.Health(), a.Backups.Offsite()
		out.Health, out.Offsite = &h, &o
	}
	for _, d := range a.Registry.All() {
		if d.Backup == nil {
			continue
		}
		g := backupOverviewGame{ID: d.ID, Name: d.DisplayName, Restorable: a.Restore != nil && d.Backup.CanRestore,
			Running: a.Backups.Running(d.ID) || (a.Restore != nil && a.Restore.Running(d.ID))}
		if files, err := a.Backups.List(r.Context(), d); err != nil {
			g.Unavailable = true
		} else {
			g.Count = len(files)
			if len(files) > 0 {
				g.Latest = &files[0]
			}
		}
		out.Games = append(out.Games, g)
	}
	writeJSON(w, http.StatusOK, out)
}
