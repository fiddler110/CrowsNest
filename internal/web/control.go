package web

import (
	"encoding/json"
	"errors"
	"github.com/fiddler110/crowsnest/internal/audit"
	"net/http"
	"strconv"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/exclusivity"
	"github.com/fiddler110/crowsnest/internal/memadmit"
)

// maxSwitchBodyBytes caps the /api/games/{id}/switch request body — it's a
// tiny fixed shape ({"from": "<id>"}), so there's no reason to let an
// authenticated client force a large json.Decode allocation.
const maxSwitchBodyBytes = 4096

// actor returns the acting username for an audit log line, falling back to
// "unknown" if for some reason no session is attached (shouldn't happen —
// these handlers all sit behind requireSessionAndCSRF).
func actor(r *http.Request) string {
	if session, ok := auth.FromContext(r.Context()); ok {
		return session.Username
	}
	return "unknown"
}

func (a *App) handleStart(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	err := a.Exclusivity.RequestStart(exclusivity.WithActor(r.Context(), actor(r)), d.ID)
	if err == nil {
		a.pokeGame(d.ID)
		audit.Printf("%s started %s", actor(r), d.ID)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var conflict *exclusivity.ConflictError
	if errors.As(err, &conflict) {
		// A game this user may not see is running: do not name it or offer
		// to stop it.
		for _, id := range conflict.All {
			if !a.canSee(r, id) {
				writeJSON(w, http.StatusConflict, map[string]any{"busy": true, "message": "Another server is running right now, so this one can't start."})
				return
			}
		}
		writeJSON(w, http.StatusConflict, map[string]any{"conflict": true, "active_game": conflict.Active, "active_games": conflict.All})
		return
	}
	var busy *exclusivity.BusyError
	if errors.As(err, &busy) {
		writeJSON(w, http.StatusConflict, map[string]any{"busy": true, "message": busy.Error()})
		return
	}
	var mem *memadmit.Error
	if errors.As(err, &mem) {
		audit.Printf("%s start %s refused: %v", actor(r), d.ID, err)
		writeJSON(w, http.StatusConflict, map[string]any{"busy": true, "message": mem.Error()})
		return
	}
	var cooldown *exclusivity.CooldownError
	if errors.As(err, &cooldown) {
		w.Header().Set("Retry-After", strconv.Itoa(int(cooldown.Remaining.Seconds())+1))
		http.Error(w, cooldown.Error(), http.StatusTooManyRequests)
		return
	}
	audit.Printf("%s start %s failed: %v", actor(r), d.ID, err)
	http.Error(w, publicError(err), http.StatusBadGateway)
}

func (a *App) handleStop(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	// Accepted, not finished: the stop runs in the background (a save can
	// outlast any proxy timeout); progress shows as the "stopping" status.
	if err := a.Exclusivity.RequestStop(exclusivity.WithActor(r.Context(), actor(r)), d.ID); err != nil {
		audit.Printf("%s stop %s failed: %v", actor(r), d.ID, err)
		http.Error(w, publicError(err), http.StatusBadGateway)
		return
	}
	a.pokeGame(d.ID)
	audit.Printf("%s requested stop of %s", actor(r), d.ID)
	w.WriteHeader(http.StatusAccepted)
}

type switchRequest struct {
	From string `json:"from"`
}

func (a *App) handleSwitch(w http.ResponseWriter, r *http.Request) {
	to, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSwitchBodyBytes)
	var req switchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.From == "" {
		http.Error(w, `invalid request: expected {"from": "<game id>"}`, http.StatusBadRequest)
		return
	}
	// From here on use the registry's own ID, never the client-supplied
	// string, so nothing a caller typed reaches the log.
	fromDef, ok := a.Registry.Get(req.From)
	if !ok || !a.canSee(r, fromDef.ID) {
		http.Error(w, "unknown source game", http.StatusBadRequest)
		return
	}
	from := fromDef.ID
	if err := a.Exclusivity.RequestSwitch(exclusivity.WithActor(r.Context(), actor(r)), from, to.ID); err != nil {
		audit.Printf("%s switch %q->%q failed: %v", actor(r), from, to.ID, err)
		var busy *exclusivity.BusyError
		if errors.As(err, &busy) {
			writeJSON(w, http.StatusConflict, map[string]any{"busy": true, "message": busy.Error()})
			return
		}
		var mem *memadmit.Error
		if errors.As(err, &mem) {
			writeJSON(w, http.StatusConflict, map[string]any{"busy": true, "message": mem.Error()})
			return
		}
		var cooldown *exclusivity.CooldownError
		if errors.As(err, &cooldown) {
			w.Header().Set("Retry-After", strconv.Itoa(int(cooldown.Remaining.Seconds())+1))
			http.Error(w, cooldown.Error(), http.StatusTooManyRequests)
			return
		}
		http.Error(w, publicError(err), http.StatusBadGateway)
		return
	}
	a.pokeGame(from)
	a.pokeGame(to.ID)
	audit.Printf("%s requested switch %q->%q", actor(r), from, to.ID)
	w.WriteHeader(http.StatusAccepted)
}
