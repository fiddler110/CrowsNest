package web

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fiddler110/crowsnest/internal/audit"
	"github.com/fiddler110/crowsnest/internal/history"
	"github.com/fiddler110/crowsnest/internal/schedule"
)

type schedulesResponse struct {
	Schedules []schedule.Entry `json:"schedules"`
	TZ        string           `json:"tz,omitempty"`
}

func (a *App) handleGetSchedules(w http.ResponseWriter, r *http.Request) {
	if a.Schedules == nil {
		http.NotFound(w, r)
		return
	}
	list := a.Schedules.List()
	if list == nil {
		list = []schedule.Entry{}
	}
	writeJSON(w, http.StatusOK, schedulesResponse{Schedules: list, TZ: a.TimeZone})
}

// handlePutSchedules replaces the whole list.
func (a *App) handlePutSchedules(w http.ResponseWriter, r *http.Request) {
	if a.Schedules == nil {
		http.NotFound(w, r)
		return
	}
	var body struct {
		Schedules []schedule.Entry `json:"schedules"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}
	known := func(id string) bool { _, ok := a.Registry.Get(id); return ok }
	if err := a.Schedules.Replace(body.Schedules, known); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	detail := fmt.Sprintf("saved %d schedule(s)", len(body.Schedules))
	audit.Printf("%s %s", actor(r), detail)
	if a.History != nil {
		a.History.Record(history.KindSettings, "", actor(r), detail)
	}
	writeJSON(w, http.StatusOK, schedulesResponse{Schedules: a.Schedules.List(), TZ: a.TimeZone})
}
