// Package web wires HTTP handlers to the game registry, Docker control
// layer, exclusivity guard, and auth service: the dashboard UI, the
// game-control JSON API, and login/logout.
package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/backup"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/exclusivity"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/history"
	"github.com/fiddler110/crowsnest/internal/hoststats"
	"github.com/fiddler110/crowsnest/internal/memadmit"
	"github.com/fiddler110/crowsnest/internal/memo"
	"github.com/fiddler110/crowsnest/internal/settings"
	"github.com/fiddler110/crowsnest/internal/statehub"
)

// App holds the dependencies HTTP handlers need.
type App struct {
	Registry    *games.Registry
	Docker      *dockerctl.Client
	Exclusivity *exclusivity.Manager
	Auth        *auth.Service
	// Google, when set, adds "Sign in with Google" (see auth.GoogleLogin).
	// Setup, when set, offers first-run setup while there are no users.
	Setup  *auth.Setup
	Google *auth.GoogleLogin
	// Settings backs the dashboard's settings dialog (/api/settings).
	Settings *settings.Store
	// TimeZone is the server's time zone name (server.tz), shown beside the
	// overnight-shutdown hours, which are local to it. Optional.
	TimeZone string
	// IdleTimer, when set, supplies each game's idle-shutdown countdown.
	IdleTimer IdleTimer
	// History backs the activity feed (/api/activity) and records settings
	// changes. Optional.
	History *history.Store
	// Backups runs and lists per-game backups (admin only). Optional.
	Backups *backup.Manager
	// Managed backs the Games API (enable games from the dashboard). Optional.
	Managed ManagedGames
	// HostPaths are the mounted paths whose free space /api/host reports.
	HostPaths []string
	Templates *Templates

	// KeepaliveInterval overrides the SSE keepalive-comment interval.
	// Intended for tests; production callers should leave it unset (falls
	// back to defaultKeepaliveInterval).
	KeepaliveInterval time.Duration

	// MaxConcurrentStreams caps how many /logs and /startup-progress SSE
	// connections (combined, across all games) may be open at once — each
	// holds open a `docker logs -f` subprocess. Intended for tests;
	// production callers should leave it unset (falls back to
	// defaultMaxConcurrentStreams).
	MaxConcurrentStreams int
	streamCount          atomic.Int32

	// MaxEventStreams caps concurrent /api/events connections. Zero means
	// defaultMaxEventStreams.
	MaxEventStreams int
	eventStreams    atomic.Int32
	// MaxEventStreamsPerUser caps one user's concurrent /api/events
	// connections. Zero means defaultMaxEventStreamsPerUser.
	MaxEventStreamsPerUser int
	userEventStreams       userStreams

	// EventsMinGap overrides the minimum spacing of /api/events sends
	// (tests). Zero means defaultEventsMinGap.
	EventsMinGap time.Duration

	// StatusTTL is how long a game's stats and info and the docker health
	// check are shared between requests; however many tabs poll, the probes
	// behind them run at most once per TTL per game. Zero means
	// defaultStatusTTL; negative disables sharing (tests). Status and player
	// counts come from Hub instead.
	StatusTTL time.Duration

	// Hub observes every game (status and players) for every handler, and
	// drives /api/events. Without one, each request probes directly.
	Hub *statehub.Hub

	hostMemo   memo.Memo[hoststats.Snapshot]
	healthMemo memo.Memo[bool]
	statsMemo  memo.Memo[statsResponse]
	infoMemo   memo.Memo[infoResult]
}

const defaultStatusTTL = 2 * time.Second

func (a *App) statusTTL() time.Duration {
	if a.StatusTTL == 0 {
		return defaultStatusTTL
	}
	return a.StatusTTL
}

// observe returns d's current observation from the hub (waiting for the
// first one, or for a fresher one after an action poked the game), or a
// direct probe when there is no hub.
func (a *App) observe(ctx context.Context, d games.GameDef) statehub.Observation {
	if a.Hub == nil {
		return statehub.Probe(ctx, d)
	}
	return a.Hub.Current(ctx, d)
}

// observeAll observes every game in parallel (a slow probe on one game must
// not delay the rest), preserving order.
func (a *App) observeAll(ctx context.Context, defs []games.GameDef) []statehub.Observation {
	out := make([]statehub.Observation, len(defs))
	var wg sync.WaitGroup
	for i, d := range defs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = a.observe(ctx, d)
		}()
	}
	wg.Wait()
	return out
}

// pokeGame asks for a fresh observation of a game after an action that
// changes it, and drops its shared stats and info, so the next read
// reflects the action.
func (a *App) pokeGame(id string) {
	if a.Hub != nil {
		a.Hub.Poke(id)
	}
	a.statsMemo.Forget(id)
	a.infoMemo.Forget(id)
}

// IdleTimer reports time left before a game is auto-stopped for being
// empty; satisfied by *idleshutdown.Manager.
type IdleTimer interface {
	IdleRemaining(id string) (time.Duration, bool)
}

// maxSwitchBodyBytes caps the /api/games/{id}/switch request body — it's a
// tiny fixed shape ({"from": "<id>"}), so there's no reason to let an
// authenticated client force a large json.Decode allocation.
const maxSwitchBodyBytes = 4096

// Routes registers the dashboard, login/logout, and game-control API on
// mux.
func (a *App) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /setup", a.handleSetupPage)
	mux.HandleFunc("POST /setup", a.handleSetup)
	mux.HandleFunc("GET /login", a.handleLoginPage)
	mux.HandleFunc("POST /login", a.Auth.ServeLogin)
	mux.HandleFunc("POST /logout", a.Auth.ServeLogout)
	if a.Google != nil {
		mux.HandleFunc("GET "+auth.GoogleStartPath, a.Google.ServeStart)
		mux.HandleFunc("GET "+auth.GoogleCallbackPath, getOnly(a.Google.ServeCallback))
	}

	mux.Handle("GET /{$}", a.requireSessionHTML(http.HandlerFunc(a.handleDashboard)))
	mux.Handle("GET /settings", a.requireSessionHTML(http.HandlerFunc(a.handleSettingsPage)))
	mux.Handle("GET /games", a.requireSessionHTML(http.HandlerFunc(a.handleGamesPage)))
	mux.Handle("GET /api/games", a.requireSession(http.HandlerFunc(a.handleListGames)))
	mux.Handle("GET /api/events", a.requireSession(http.HandlerFunc(a.handleEvents)))
	mux.Handle("GET /api/games/{id}/status", a.requireSession(http.HandlerFunc(a.handleStatus)))
	mux.Handle("GET /api/games/{id}/logs", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleLogs)))) // S8: logs can carry secrets an image prints
	mux.Handle("GET /api/games/{id}/startup-progress", a.requireSession(http.HandlerFunc(a.handleStartupProgress)))
	mux.Handle("GET /api/games/{id}/stats", a.requireSession(http.HandlerFunc(a.handleStats)))
	mux.Handle("GET /api/games/{id}/players", a.requireSession(http.HandlerFunc(a.handlePlayers)))
	mux.Handle("GET /api/games/{id}/info", a.requireSession(http.HandlerFunc(a.handleInfo)))
	mux.Handle("GET /api/activity", a.requireSession(http.HandlerFunc(a.handleActivity)))
	mux.Handle("GET /api/games/{id}/console", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleConsole))))
	mux.Handle("POST /api/games/{id}/console/action", a.requireAdmin(http.HandlerFunc(a.handleConsoleAction)))
	mux.Handle("POST /api/games/{id}/console/raw", a.requireAdmin(http.HandlerFunc(a.handleConsoleRaw)))
	mux.Handle("POST /api/games/{id}/backup", a.requireAdmin(http.HandlerFunc(a.handleBackup)))
	mux.Handle("GET /api/games/{id}/backups", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleBackups))))
	mux.Handle("GET /api/host", a.requireSession(http.HandlerFunc(a.handleHost)))
	mux.Handle("GET /api/health", a.requireSession(http.HandlerFunc(a.handleHealth)))
	mux.Handle("GET /api/settings", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleGetSettings))))
	mux.Handle("PUT /api/settings", a.requireAdmin(http.HandlerFunc(a.handlePutSettings)))
	mux.Handle("GET /api/managed/modules", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleManagedModules))))
	mux.Handle("GET /api/managed/configured", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleManagedConfigured))))
	mux.Handle("GET /api/managed/policy", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleManagedPolicy))))
	mux.Handle("PUT /api/managed/modules/{id}/allow", a.requireAdmin(http.HandlerFunc(a.handleManagedAllow)))
	mux.Handle("PUT /api/managed/policy", a.requireAdmin(http.HandlerFunc(a.handleManagedSetPolicy)))
	mux.Handle("GET /api/managed/games", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleManagedList))))
	mux.Handle("POST /api/managed/preview", a.requireAdmin(http.HandlerFunc(a.handleManagedPreview)))
	mux.Handle("POST /api/managed/games", a.requireAdmin(http.HandlerFunc(a.handleManagedEnable)))
	mux.Handle("PUT /api/managed/games/{id}", a.requireAdmin(http.HandlerFunc(a.handleManagedUpdate)))
	mux.Handle("POST /api/managed/games/{id}/refresh", a.requireAdmin(http.HandlerFunc(a.handleManagedRefresh)))
	mux.Handle("POST /api/managed/games/{id}/rollback", a.requireAdmin(http.HandlerFunc(a.handleManagedRollback)))
	mux.Handle("DELETE /api/managed/games/{id}", a.requireAdmin(http.HandlerFunc(a.handleManagedDisable)))
	mux.Handle("GET /api/users", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleListUsers))))
	mux.Handle("POST /api/users", a.requireAdmin(http.HandlerFunc(a.handleCreateUser)))
	mux.Handle("PUT /api/users/{name}", a.requireAdmin(http.HandlerFunc(a.handleUpdateUser)))
	mux.Handle("DELETE /api/users/{name}", a.requireAdmin(http.HandlerFunc(a.handleDeleteUser)))
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

// requireAdmin is requireSessionAndCSRF plus an admin-role check.
func (a *App) requireAdmin(next http.Handler) http.Handler {
	return auth.RequireSession(a.Auth.Sessions, auth.RequireCSRF(auth.RequireAdmin(a.Auth.Sessions, next)))
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

	// AutoStop is false for a game with no way to count players, which idle
	// and night shutdown therefore never stop (they won't guess it's empty).
	AutoStop bool `json:"auto_stop"`

	// IdleSecondsLeft is the seconds until idle shutdown stops this game,
	// or nil when no countdown is running (idle shutdown off, game not
	// online, players aboard, or count unreadable).
	IdleSecondsLeft *int `json:"idle_seconds_left"`

	// StartError is the error from this game's most recent background
	// start, if it failed; StartErrorAt is when (unix seconds), so the UI
	// can tell a new failure from one it has already shown.
	StartError   string `json:"start_error,omitempty"`
	StartErrorAt int64  `json:"start_error_at,omitempty"`
}

// gameStatus overlays the exclusivity manager's in-memory view on an
// observed status: a game being stopped reports stopping, and one whose
// start was accepted but is still pulling/creating its container reports
// starting even though docker doesn't show it running yet. The overlay is
// never cached, so it flips the moment an action is accepted.
func (a *App) gameStatus(d games.GameDef, observed games.Status) games.Status {
	if a.Exclusivity != nil {
		if a.Exclusivity.Stopping(d.ID) {
			return games.StatusStopping
		}
		if a.Exclusivity.Starting(d.ID) && observed != games.StatusOnline {
			return games.StatusStarting
		}
	}
	return observed
}

// loginPage is the login template's data. Error is one of a fixed set of
// messages chosen by code, never text taken from the request.
type loginPage struct {
	PasswordLogin  bool
	GoogleStartURL string
	Error          string
}

var loginErrors = map[string]string{
	auth.LoginErrorDenied:     "Google sign-in was cancelled.",
	auth.LoginErrorExpired:    "That sign-in attempt expired. Please try again.",
	auth.LoginErrorNotAllowed: "That Google account isn't on this ship's crew list.",
	auth.LoginErrorFailed:     "Google sign-in failed. Please try again.",
	auth.LoginErrorRateLimit:  "Too many sign-in attempts. Try again in a few minutes.",
}

func (a *App) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if a.setupNeeded() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	page := loginPage{PasswordLogin: !a.Auth.DisablePasswordLogin, Error: loginErrors[r.URL.Query().Get("error")]}
	if a.Google != nil {
		page.GoogleStartURL = a.Google.StartURL()
	}
	render(w, a.Templates.Login, page, "login page")
}

type dashboardGame struct {
	ID          string
	DisplayName string
	Initial     string // first letter, for the card's emblem
	Status      string

	// ConnectAddress/ConnectNote are the optional display-only connection
	// details; the template renders nothing when both are empty.
	ConnectAddress string
	ConnectNote    string
	ConnectSecrets []games.ConnectSecret

	// HasBackup is true when a backup is configured and the viewer is an
	// admin, which is the only role that sees the Backups panel.
	HasBackup bool

	// HasConsole is true for admins on games that offer console actions.
	HasConsole bool

	// HasInfo is true when the game has an info provider; otherwise the card
	// has no Info tab.
	HasInfo bool

	// Accent is the card's "#rrggbb" accent from the game's module, or empty.
	Accent string
}

// dashboardData is the data of every signed-in page. Page names the page
// ("dashboard", "games", "settings") so the shared top bar can mark it.
type dashboardData struct {
	Page      string
	Username  string
	IsAdmin   bool
	CSRFToken string
	Games     []dashboardGame
	// NeedsPassword: an admin with no stored password sees a banner, because
	// widening the guard asks for one.
	NeedsPassword bool
}

func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := auth.FromContext(r.Context())
	defs := a.Registry.All()
	data := dashboardData{
		Page:          "dashboard",
		Username:      session.Username,
		IsAdmin:       a.Auth.Sessions.RoleFor(session.Username) == auth.RoleAdmin,
		NeedsPassword: a.Auth.Sessions.RoleFor(session.Username) == auth.RoleAdmin && !a.Auth.HasPassword(session.Username),
		CSRFToken:     session.CSRFToken,
	}
	// First paint must not wait on game probes (a booting game's API can
	// take seconds to time out): use the hub's latest observation if any,
	// else "unknown"; the page's JS refreshes statuses immediately on load.
	for _, d := range defs {
		snap := statehub.Observation{Status: games.StatusUnknown}
		if a.Hub != nil {
			if o, ok := a.Hub.Get(d.ID); ok {
				snap = o
			}
		}
		data.Games = append(data.Games, dashboardGame{
			ID:          d.ID,
			DisplayName: d.DisplayName,
			Initial:     initialOf(d.DisplayName),
			Status:      a.gameStatus(d, snap.Status).String(),

			ConnectAddress: d.ConnectAddress,
			ConnectNote:    d.ConnectNote,
			ConnectSecrets: d.ConnectSecrets,
			HasBackup:      data.IsAdmin && d.Backup != nil && a.Backups != nil,
			HasConsole:     data.IsAdmin && d.Console != nil,
			HasInfo:        d.Info != nil,
			Accent:         d.Accent,
		})
	}
	render(w, a.Templates.Dashboard, data, "dashboard")
}

func (a *App) handleListGames(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.listGames(r))
}

// listGames builds the /api/games body for r's user (admins see raw error
// detail); /api/events sends the same.
func (a *App) listGames(r *http.Request) []gameSummary {
	defs := a.Registry.All()
	out := make([]gameSummary, len(defs))
	snaps := a.observeAll(r.Context(), defs)
	admin := a.Auth.Sessions.RoleFor(actor(r)) == auth.RoleAdmin
	for i, d := range defs {
		out[i] = gameSummary{
			ID:          d.ID,
			DisplayName: d.DisplayName,
			Status:      a.gameStatus(d, snaps[i].Status).String(),
			AutoStop:    games.CanCountPlayers(d),
		}
		if snaps[i].PlayersOK {
			c := snaps[i].Count
			out[i].PlayerCount = &c
		}
		if a.IdleTimer != nil && out[i].Status == games.StatusOnline.String() {
			if left, ok := a.IdleTimer.IdleRemaining(d.ID); ok {
				secs := int(left.Seconds())
				out[i].IdleSecondsLeft = &secs
			}
		}
		if a.Exclusivity != nil {
			if res, ok := a.Exclusivity.LastStart(d.ID); ok && res.Err != "" {
				out[i].StartError = res.Err
				if admin && res.Detail != "" {
					out[i].StartError = shortDetail(res.Detail)
				}
				out[i].StartErrorAt = res.At.Unix()
			}
		}
	}
	return out
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
	snap := a.observe(r.Context(), d)
	if d.Players == nil || !snap.PlayersOK {
		writeJSON(w, http.StatusOK, playersResponse{})
		return
	}
	names := snap.Names
	if names == nil {
		names = []string{}
	}
	writeJSON(w, http.StatusOK, playersResponse{Available: true, Count: snap.Count, Names: names})
}

// shortDetail keeps the tail of raw error text (where the cause usually is)
// on one line, for admins.
func shortDetail(msg string) string {
	msg = strings.Join(strings.Fields(msg), " ")
	if r := []rune(msg); len(r) > 400 {
		msg = "…" + string(r[len(r)-400:])
	}
	return msg
}

const (
	defaultActivityLimit = 40
	maxActivityLimit     = 500
)

// handleActivity returns the newest activity events (optionally for one
// game) and the playtime totals derived from join/leave events.
func (a *App) handleActivity(w http.ResponseWriter, r *http.Request) {
	if a.History == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []history.Event{}, "playtime": []history.Playtime{}})
		return
	}
	limit := defaultActivityLimit
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = min(n, maxActivityLimit)
	}
	var hide []string
	if a.Auth.Sessions.RoleFor(actor(r)) != auth.RoleAdmin {
		hide = []string{history.KindUsers, history.KindConsole, history.KindSettings, history.KindGames}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events":   a.History.RecentExcluding(limit, r.URL.Query().Get("game"), hide...),
		"playtime": a.History.Playtime(),
	})
}

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
		log.Printf("audit: %s requested backup of %s", actor(r), d.ID)
		w.WriteHeader(http.StatusAccepted)
	case errors.Is(err, backup.ErrNotConfigured):
		http.Error(w, "this game has no backup configured", http.StatusNotFound)
	case errors.Is(err, backup.ErrNotRunning), errors.Is(err, backup.ErrBusy):
		http.Error(w, strings.TrimPrefix(err.Error(), "backup: "), http.StatusConflict)
	default:
		log.Printf("audit: %s backup %s failed: %v", actor(r), d.ID, err)
		http.Error(w, publicError(err), http.StatusBadGateway)
	}
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
	files, err := a.Backups.List(r.Context(), d)
	switch {
	case errors.Is(err, backup.ErrNotConfigured):
		writeJSON(w, http.StatusOK, map[string]any{"files": []backup.File{}, "running": a.Backups.Running(d.ID)})
	case err != nil:
		// Usually just "the container isn't running".
		writeJSON(w, http.StatusOK, map[string]any{"files": []backup.File{}, "running": a.Backups.Running(d.ID), "unavailable": true})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"files": files, "running": a.Backups.Running(d.ID)})
	}
}

// handleHost reports host memory, load and disk space.
func (a *App) handleHost(w http.ResponseWriter, r *http.Request) {
	snap, err := a.hostMemo.Do(r.Context(), "host", 5*time.Second, func(context.Context) hoststats.Snapshot {
		return hoststats.Read(a.HostPaths)
	})
	if err != nil {
		http.Error(w, "host stats unavailable", http.StatusGatewayTimeout)
		return
	}
	if snap.Disks == nil {
		snap.Disks = []hoststats.Disk{}
	}
	writeJSON(w, http.StatusOK, snap)
}

// handleHealth reports whether CrowsNest can reach Docker. It's separate from
// /healthz, the container liveness probe: a restart wouldn't fix a stopped
// daemon, so liveness stays green while this goes red and the dashboard warns.
// The reason is logged, not returned.
func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.health(r.Context()))
}

// health is the /api/health body; /api/events sends the same.
func (a *App) health(ctx context.Context) map[string]bool {
	ok, err := a.healthMemo.Do(ctx, "docker", a.statusTTL(), func(ctx context.Context) bool {
		if err := a.Docker.Ping(ctx); err != nil {
			log.Printf("web: docker unreachable: %v", err)
			return false
		}
		return true
	})
	return map[string]bool{"docker": err == nil && ok}
}

type infoResult struct {
	data map[string]any
	ok   bool
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
	res, err := a.infoMemo.Do(r.Context(), d.ID, a.statusTTL(), func(ctx context.Context) infoResult {
		data, ok := d.Info.Info(ctx)
		return infoResult{data: data, ok: ok}
	})
	data, ok := res.data, res.ok
	if err != nil || !ok {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	// An InfoProvider reporting success means the data is available; don't
	// make every provider remember to say so (the dashboard keys off it).
	out := make(map[string]any, len(data)+1)
	for k, v := range data {
		out[k] = v
	}
	if _, set := out["available"]; !set {
		out["available"] = true
	}
	writeJSON(w, http.StatusOK, out)
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
	writeJSON(w, http.StatusOK, map[string]string{"status": a.gameStatus(d, a.observe(r.Context(), d).Status).String()})
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

	// `docker stats --no-stream` takes a second or more, so it is shared
	// between tabs like everything else (and 3s of staleness is invisible).
	resp, err := a.statsMemo.Do(r.Context(), d.ID, a.statusTTL(), func(ctx context.Context) statsResponse {
		var resp statsResponse
		if s, err := a.Docker.Stats(ctx, d.ContainerName); err == nil {
			resp.CPU = strPtr(s.CPUPercent)
			resp.MemUsed = strPtr(s.MemUsed)
			resp.MemTotal = strPtr(s.MemTotal)
			resp.MemPercent = strPtr(s.MemPercent)
		}
		if g, ok := a.Docker.GPUStats(ctx); ok {
			resp.GPUUtil = strPtr(g.UtilPercent)
			resp.GPUMemUsed = strPtr(g.MemUsedMiB + " MiB")
			resp.GPUMemTotal = strPtr(g.MemTotalMiB + " MiB")
		}
		return resp
	})
	if err != nil {
		http.Error(w, "stats unavailable", http.StatusGatewayTimeout)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

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
		log.Printf("audit: %s started %s", actor(r), d.ID)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var conflict *exclusivity.ConflictError
	if errors.As(err, &conflict) {
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
		log.Printf("audit: %s start %s refused: %v", actor(r), d.ID, err)
		writeJSON(w, http.StatusConflict, map[string]any{"busy": true, "message": mem.Error()})
		return
	}
	var cooldown *exclusivity.CooldownError
	if errors.As(err, &cooldown) {
		w.Header().Set("Retry-After", strconv.Itoa(int(cooldown.Remaining.Seconds())+1))
		http.Error(w, cooldown.Error(), http.StatusTooManyRequests)
		return
	}
	log.Printf("audit: %s start %s failed: %v", actor(r), d.ID, err)
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
		log.Printf("audit: %s stop %s failed: %v", actor(r), d.ID, err)
		http.Error(w, publicError(err), http.StatusBadGateway)
		return
	}
	a.pokeGame(d.ID)
	log.Printf("audit: %s requested stop of %s", actor(r), d.ID)
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
	if !ok {
		http.Error(w, "unknown source game", http.StatusBadRequest)
		return
	}
	from := fromDef.ID
	if err := a.Exclusivity.RequestSwitch(exclusivity.WithActor(r.Context(), actor(r)), from, to.ID); err != nil {
		log.Printf("audit: %s switch %q->%q failed: %v", actor(r), from, to.ID, err)
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
	log.Printf("audit: %s requested switch %q->%q", actor(r), from, to.ID)
	w.WriteHeader(http.StatusAccepted)
}

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
		log.Printf("audit: %s settings update failed: %v", actor(r), err)
		http.Error(w, "could not save settings", http.StatusInternalServerError)
		return
	}
	if a.History != nil {
		a.History.Record(history.KindSettings, "", actor(r), settingsChanges(before, v))
	}
	log.Printf("audit: %s updated settings: %+v", actor(r), v)
	writeJSON(w, http.StatusOK, v)
}

// publicError is what a client is told about an internal failure: the
// details (docker command lines, compose paths, stderr) stay in the log.
func publicError(err error) string {
	var busy *exclusivity.BusyError
	var mem *memadmit.Error
	if errors.As(err, &busy) || errors.As(err, &mem) {
		return err.Error()
	}
	return "the request could not be completed; see the CrowsNest log for details"
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
	add("auto_update", before.AutoUpdate, after.AutoUpdate)
	add("raw_console", before.RawConsole, after.RawConsole)
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// initialOf returns the upper-cased first letter of name (or "?" if empty).
func initialOf(name string) string {
	for _, r := range name {
		return strings.ToUpper(string(r))
	}
	return "?"
}

// getOnly rejects HEAD on a GET route. Go's "GET" pattern also matches HEAD, and a
// HEAD to the OAuth callback would consume the one-time state cookie.
func getOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}
