package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fiddler110/crowsnest/internal/audit"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/history"
	"github.com/fiddler110/crowsnest/internal/settings"
)

const maxSettingsBodyBytes = 4096

func (a *App) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if a.Settings == nil {
		http.NotFound(w, r)
		return
	}
	// tz rides along for display only; PUT decodes settings.Values alone (and
	// refuses unknown fields), so the page must not send it back.
	resp := settingsResponse{Values: a.Settings.Get(), TZ: a.TimeZone}
	for _, d := range a.Registry.All() {
		resp.Games = append(resp.Games, gameSettingsInfo{
			ID: d.ID, Name: d.DisplayName,
			NightShutdown:          d.NightShutdown,
			RestartCooldownSeconds: int(d.RestartCooldown / time.Second),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// gameSettingsInfo is one game's own defaults, shown beside its overrides.
type gameSettingsInfo struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	NightShutdown          bool   `json:"night_shutdown"`
	RestartCooldownSeconds int    `json:"restart_cooldown_seconds"`
}

// settingsResponse is GET /api/settings: the values plus the server's time
// zone, which the overnight hours are local to.
type settingsResponse struct {
	settings.Values
	TZ string `json:"tz,omitempty"`
	// Games lists the registered games with their defaults, for the
	// per-game overrides in per_game.
	Games []gameSettingsInfo `json:"games,omitempty"`
}

func (a *App) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	if a.Settings == nil {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSettingsBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid settings: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Applied under the store's lock on top of the current values, so a
	// partial body only changes what it names and two simultaneous saves
	// can't overwrite each other.
	before := a.Settings.Get()
	var invalid error
	v, err := a.Settings.Modify(func(v *settings.Values) error {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			invalid = errors.New("invalid settings: " + err.Error())
			return invalid
		}
		if err := v.Validate(); err != nil {
			invalid = err
			return err
		}
		return nil
	})
	if invalid != nil {
		http.Error(w, invalid.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		audit.Printf("%s settings update failed: %v", actor(r), err)
		http.Error(w, "could not save settings", http.StatusInternalServerError)
		return
	}
	if a.History != nil {
		a.History.Record(history.KindSettings, "", actor(r), settingsChanges(before, v))
	}
	audit.Printf("%s updated settings: %+v", actor(r), v)
	writeJSON(w, http.StatusOK, v)
}

// settingsChanges describes which settings differ, e.g. "idle_minutes 15→30".
func settingsChanges(before, after settings.Values) string {
	var parts []string
	add := func(name string, b, a any) {
		if b != a {
			parts = append(parts, fmt.Sprintf("%s %v→%v", name, b, a))
		}
	}
	add("idle_enabled", before.IdleEnabled, after.IdleEnabled)
	add("idle_minutes", before.IdleMinutes, after.IdleMinutes)
	add("night_enabled", before.NightEnabled, after.NightEnabled)
	add("night_start_hour", before.NightStartHour, after.NightStartHour)
	add("night_end_hour", before.NightEndHour, after.NightEndHour)
	add("max_active_games", before.MaxActiveGames, after.MaxActiveGames)
	add("raw_console", before.RawConsole, after.RawConsole)
	add("require_admin_mfa", before.RequireAdminMFA, after.RequireAdminMFA)
	ids := map[string]bool{}
	for id := range before.PerGame {
		ids[id] = true
	}
	for id := range after.PerGame {
		ids[id] = true
	}
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		add(id, describeGameValues(before.PerGame[id]), describeGameValues(after.PerGame[id]))
	}
	if len(parts) == 0 {
		return "no changes"
	}
	return strings.Join(parts, ", ")
}

// describeGameValues renders one game's overrides, "default" when it has none.
func describeGameValues(g settings.GameValues) string {
	var parts []string
	if g.IdleMinutes != nil {
		parts = append(parts, fmt.Sprintf("idle %dm", *g.IdleMinutes))
	}
	if g.NightShutdown != nil {
		parts = append(parts, fmt.Sprintf("night %t", *g.NightShutdown))
	}
	if g.RestartCooldownSeconds != nil {
		parts = append(parts, fmt.Sprintf("cooldown %ds", *g.RestartCooldownSeconds))
	}
	if len(parts) == 0 {
		return "default"
	}
	return strings.Join(parts, " ")
}
