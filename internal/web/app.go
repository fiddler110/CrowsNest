// Package web wires HTTP handlers to the game registry, Docker control
// layer, exclusivity guard, and auth service: the dashboard UI, the
// game-control JSON API, and login/logout.
package web

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/exclusivity"
	"github.com/fiddler110/crowsnest/internal/games"
)

// App holds the dependencies HTTP handlers need.
type App struct {
	Registry    *games.Registry
	Docker      *dockerctl.Client
	Exclusivity *exclusivity.Manager
	Auth        *auth.Service
	Templates   *Templates

	// KeepaliveInterval overrides the SSE keepalive-comment interval.
	// Intended for tests; production callers should leave it unset (falls
	// back to defaultKeepaliveInterval).
	KeepaliveInterval time.Duration
}

// Routes registers the dashboard, login/logout, and game-control API on
// mux.
func (a *App) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", a.handleLoginPage)
	mux.HandleFunc("POST /login", a.Auth.ServeLogin)
	mux.HandleFunc("POST /logout", a.Auth.ServeLogout)

	mux.Handle("GET /{$}", a.requireSessionHTML(http.HandlerFunc(a.handleDashboard)))
	mux.Handle("GET /api/games", a.requireSession(http.HandlerFunc(a.handleListGames)))
	mux.Handle("GET /api/games/{id}/status", a.requireSession(http.HandlerFunc(a.handleStatus)))
	mux.Handle("GET /api/games/{id}/logs", a.requireSession(http.HandlerFunc(a.handleLogs)))
	mux.Handle("GET /api/games/{id}/startup-progress", a.requireSession(http.HandlerFunc(a.handleStartupProgress)))
	mux.Handle("GET /api/games/{id}/stats", a.requireSession(http.HandlerFunc(a.handleStats)))
	mux.Handle("GET /api/games/{id}/players", a.requireSession(http.HandlerFunc(a.handlePlayers)))
	mux.Handle("GET /api/games/{id}/info", a.requireSession(http.HandlerFunc(a.handleInfo)))
	mux.Handle("POST /api/games/{id}/start", a.requireSessionAndCSRF(http.HandlerFunc(a.handleStart)))
	mux.Handle("POST /api/games/{id}/switch", a.requireSessionAndCSRF(http.HandlerFunc(a.handleSwitch)))
	mux.Handle("POST /api/games/{id}/stop", a.requireSessionAndCSRF(http.HandlerFunc(a.handleStop)))

	if static, err := staticHandler(); err != nil {
		log.Printf("web: static assets unavailable: %v", err)
	} else {
		mux.Handle("GET /static/", http.StripPrefix("/static/", static))
	}
}

func (a *App) requireSession(next http.Handler) http.Handler {
	return auth.RequireSession(a.Auth.Sessions, next)
}

func (a *App) requireSessionAndCSRF(next http.Handler) http.Handler {
	return auth.RequireSession(a.Auth.Sessions, auth.RequireCSRF(next))
}

// requireSessionHTML is like requireSession but redirects to the login page
// on failure instead of returning 401 JSON — appropriate for a page a
// browser navigates to directly.
func (a *App) requireSessionHTML(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := auth.DecodeSessionCookie(a.Auth.Sessions, r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithSession(r.Context(), session)))
	})
}

type gameSummary struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`

	// PlayerCount is nil when the game has no PlayerCounter wired, or its
	// count is currently undeterminable — never a guessed zero.
	PlayerCount *int `json:"player_count"`
}

// playerCount reports d's current player count, if determinable.
func playerCount(r *http.Request, d games.GameDef) *int {
	if d.Players == nil {
		return nil
	}
	count, _, ok := d.Players.PlayerCount(r.Context())
	if !ok {
		return nil
	}
	return &count
}

func checkStatus(r *http.Request, d games.GameDef) games.Status {
	if d.Status == nil {
		return games.StatusUnknown
	}
	status, err := d.Status.Check(r.Context(), d.ContainerName)
	if err != nil {
		return games.StatusUnknown
	}
	return status
}

func (a *App) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if err := a.Templates.Login.Execute(w, nil); err != nil {
		log.Printf("web: render login page: %v", err)
	}
}

type dashboardGame struct {
	ID          string
	DisplayName string
	Status      string
}

type dashboardData struct {
	Username  string
	CSRFToken string
	Games     []dashboardGame
}

func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := auth.FromContext(r.Context())
	defs := a.Registry.All()
	data := dashboardData{Username: session.Username, CSRFToken: session.CSRFToken}
	for _, d := range defs {
		data.Games = append(data.Games, dashboardGame{ID: d.ID, DisplayName: d.DisplayName, Status: checkStatus(r, d).String()})
	}
	if err := a.Templates.Dashboard.Execute(w, data); err != nil {
		log.Printf("web: render dashboard: %v", err)
	}
}

func (a *App) handleListGames(w http.ResponseWriter, r *http.Request) {
	defs := a.Registry.All()
	out := make([]gameSummary, len(defs))
	for i, d := range defs {
		out[i] = gameSummary{
			ID:          d.ID,
			DisplayName: d.DisplayName,
			Status:      checkStatus(r, d).String(),
			PlayerCount: playerCount(r, d),
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// playersResponse is the /api/games/{id}/players shape. Available is false
// whenever the game has no PlayerCounter wired or its count is currently
// undeterminable; Count/Names are meaningless in that case.
type playersResponse struct {
	Available bool     `json:"available"`
	Count     int      `json:"count"`
	Names     []string `json:"names"`
}

func (a *App) handlePlayers(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	if d.Players == nil {
		writeJSON(w, http.StatusOK, playersResponse{})
		return
	}
	count, names, avail := d.Players.PlayerCount(r.Context())
	if !avail {
		writeJSON(w, http.StatusOK, playersResponse{})
		return
	}
	writeJSON(w, http.StatusOK, playersResponse{Available: true, Count: count, Names: names})
}

// handleInfo reports a game's optional rich info panel data (world
// time/weather/multipliers/memory for Windrose, currently — see
// games.InfoProvider). {"available": false} for any game without one
// wired, or when the provider itself couldn't reach its data source.
func (a *App) handleInfo(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	if d.Info == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	data, ok := d.Info.Info(r.Context())
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func (a *App) gameOr404(w http.ResponseWriter, r *http.Request) (games.GameDef, bool) {
	id := r.PathValue("id")
	d, ok := a.Registry.Get(id)
	if !ok {
		http.Error(w, "game not found", http.StatusNotFound)
		return games.GameDef{}, false
	}
	return d, true
}

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": checkStatus(r, d).String()})
}

// statsResponse mirrors the original Python CrowsNest's /api/stats shape:
// each field is null (an absent pointer) when it couldn't be determined —
// container not running, docker/nvidia-smi unavailable — rather than an
// error, so the dashboard can render "N/A" per field instead of failing the
// whole panel.
type statsResponse struct {
	CPU         *string `json:"cpu"`
	MemUsed     *string `json:"mem_used"`
	MemTotal    *string `json:"mem_total"`
	MemPercent  *string `json:"mem_pct"`
	GPUUtil     *string `json:"gpu_util"`
	GPUMemUsed  *string `json:"gpu_mem_used"`
	GPUMemTotal *string `json:"gpu_mem_total"`
}

func strPtr(s string) *string { return &s }

// handleStats reports docker stats (CPU/memory) for one game's container
// plus host-level GPU utilization via nvidia-smi, if present — direct
// equivalent of the original Python CrowsNest's /api/stats, generalized to
// per-game containers (GPU stats stay host-wide, since a host has one GPU
// shared by whichever game is running).
func (a *App) handleStats(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}

	var resp statsResponse
	if s, err := a.Docker.Stats(r.Context(), d.ContainerName); err == nil {
		resp.CPU = strPtr(s.CPUPercent)
		resp.MemUsed = strPtr(s.MemUsed)
		resp.MemTotal = strPtr(s.MemTotal)
		resp.MemPercent = strPtr(s.MemPercent)
	}
	if g, ok := a.Docker.GPUStats(r.Context()); ok {
		resp.GPUUtil = strPtr(g.UtilPercent)
		resp.GPUMemUsed = strPtr(g.MemUsedMiB + " MiB")
		resp.GPUMemTotal = strPtr(g.MemTotalMiB + " MiB")
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) handleStart(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	err := a.Exclusivity.RequestStart(r.Context(), d.ID)
	if err == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var conflict *exclusivity.ConflictError
	if errors.As(err, &conflict) {
		writeJSON(w, http.StatusConflict, map[string]any{"conflict": true, "active_game": conflict.Active})
		return
	}
	http.Error(w, err.Error(), http.StatusBadGateway)
}

func (a *App) handleStop(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	if err := a.Exclusivity.Stop(r.Context(), d.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
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
	var req switchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.From == "" {
		http.Error(w, `invalid request: expected {"from": "<game id>"}`, http.StatusBadRequest)
		return
	}
	if _, ok := a.Registry.Get(req.From); !ok {
		http.Error(w, "unknown source game", http.StatusBadRequest)
		return
	}
	if err := a.Exclusivity.ConfirmSwitch(r.Context(), req.From, to.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
