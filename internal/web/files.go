package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/fiddler110/crowsnest/internal/audit"
	"github.com/fiddler110/crowsnest/internal/gamefiles"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/history"
)

const maxFileBody = 2 << 20 // content plus JSON escaping of a file of at most gamefiles.AbsoluteMax

// fileOr404 finds the game and the declared file named in the path. Admin routes only.
func (a *App) fileOr404(w http.ResponseWriter, r *http.Request) (games.GameDef, gamefiles.Spec, bool) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return d, gamefiles.Spec{}, false
	}
	if a.Files == nil {
		http.Error(w, "editing files is not configured", http.StatusNotFound)
		return d, gamefiles.Spec{}, false
	}
	sp, ok := gamefiles.Find(d.Files, r.PathValue("file"))
	if !ok {
		http.Error(w, "this game has no such file", http.StatusNotFound)
		return d, sp, false
	}
	return d, sp, true
}

// fileError writes the reply for a failed read or write.
func (a *App) fileError(w http.ResponseWriter, d games.GameDef, err error) {
	switch {
	case errors.Is(err, gamefiles.ErrChanged):
		http.Error(w, "The file changed since you opened it (the game may have rewritten it). Reload it and make your change again.", http.StatusConflict)
	case errors.Is(err, gamefiles.ErrNotRunning):
		http.Error(w, "The game is stopped and this file can only be edited while it runs. Start the game first.", http.StatusConflict)
	case errors.Is(err, gamefiles.ErrTooLarge), errors.Is(err, gamefiles.ErrNotText), errors.Is(err, gamefiles.ErrHiddenValue):
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	default:
		log.Printf("web: files %s: %v", d.ID, err)
		http.Error(w, "Could not reach the file. Is the game running? Files are read and written inside its container, so it must be started (see the CrowsNest log for the reason).", http.StatusBadGateway)
	}
}

// handleFiles lists the files a game declares.
func (a *App) handleFiles(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	if a.Files == nil || len(d.Files) == 0 {
		http.Error(w, "this game has no editable files", http.StatusNotFound)
		return
	}
	running := d.Status != nil && a.gameStatus(d, a.observe(r.Context(), d).Status) != games.StatusOffline
	type fileInfo struct {
		gamefiles.Spec
		// WhenStopped: the file can be edited while the game is stopped (through a short-lived helper container).
		WhenStopped bool `json:"when_stopped"`
	}
	files := make([]fileInfo, len(d.Files))
	for i, sp := range d.Files {
		files[i] = fileInfo{sp, a.Files.CanEditStopped(d.ID, sp)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files, "running": running})
}

// handleFileGet returns one file, with redacted values hidden, and its hash.
func (a *App) handleFileGet(w http.ResponseWriter, r *http.Request) {
	d, sp, ok := a.fileOr404(w, r)
	if !ok {
		return
	}
	content, hash, err := a.Files.Read(r.Context(), d.ID, d.ContainerName, sp)
	if err != nil {
		a.fileError(w, d, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"file": sp, "content": sp.Hide(content), "sha256": hash})
}

// handleFilePut saves a file. The body carries the content, the hash the editor opened, and the admin's password.
func (a *App) handleFilePut(w http.ResponseWriter, r *http.Request) {
	d, sp, ok := a.fileOr404(w, r)
	if !ok {
		return
	}
	var b struct {
		Content  string `json:"content"`
		Base     string `json:"base_sha256"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxFileBody)).Decode(&b); err != nil || b.Base == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !a.stepUp(w, r, b.Password, fmt.Sprintf("edit %s of %s", sp.ID, d.ID)) {
		return
	}
	newHash, err := a.Files.Write(r.Context(), d.ID, d.ContainerName, sp, b.Content, b.Base)
	detail := fmt.Sprintf("edited %s (%s) of %s", sp.Label, sp.ID, d.ID)
	if err != nil {
		audit.Printf("%s edit %s/%s failed: %v (base %s)", actor(r), d.ID, sp.ID, err, b.Base)
		if a.History != nil {
			a.History.Record(history.KindFiles, d.ID, actor(r), detail+" (failed)")
		}
		a.fileError(w, d, err)
		return
	}
	audit.Printf("%s edited %s/%s: %s -> %s", actor(r), d.ID, sp.ID, b.Base, newHash)
	if a.History != nil {
		a.History.Record(history.KindFiles, d.ID, actor(r), detail)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sha256": newHash, "changed": newHash != b.Base, "restart": sp.Restart})
}

func (a *App) handleFileHistory(w http.ResponseWriter, r *http.Request) {
	d, sp, ok := a.fileOr404(w, r)
	if !ok {
		return
	}
	vs, err := a.Files.History(d.ID, sp)
	if err != nil {
		log.Printf("web: files history %s: %v", d.ID, err)
		http.Error(w, "could not read the history", http.StatusInternalServerError)
		return
	}
	if vs == nil {
		vs = []gamefiles.Version{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": vs})
}

func (a *App) handleFileVersion(w http.ResponseWriter, r *http.Request) {
	d, sp, ok := a.fileOr404(w, r)
	if !ok {
		return
	}
	content, err := a.Files.Version(d.ID, sp, r.PathValue("version"))
	if errors.Is(err, os.ErrNotExist) {
		http.Error(w, "no such version", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("web: files version %s: %v", d.ID, err)
		http.Error(w, "could not read that version", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"content": sp.Hide(content)})
}
