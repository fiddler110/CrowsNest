// Package web wires HTTP handlers to the game registry, Docker control
// layer, exclusivity guard, and auth service: the dashboard UI, the
// game-control JSON API, and login/logout.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/fiddler110/crowsnest/internal/gamefiles"
	"github.com/fiddler110/crowsnest/internal/notify"
	"log"
	"net/http"
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
	"github.com/fiddler110/crowsnest/internal/mfa"
	"github.com/fiddler110/crowsnest/internal/modules"
	"github.com/fiddler110/crowsnest/internal/restore"
	"github.com/fiddler110/crowsnest/internal/schedule"
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
	// GoogleConf holds the Google sign-in settings saved from the dashboard;
	// nil means they can't be edited there.
	GoogleConf *auth.GoogleConfStore
	// AuthPrefs holds the sign-in choices saved from the dashboard (password
	// sign-in on or off); nil means they can't be changed there.
	AuthPrefs *auth.PrefsStore
	// MFA is the TOTP second-factor store; nil turns the feature off.
	MFA *mfa.Store
	// Modules, ModulesDir and TrustedKeys let an admin install a signed module from a URL; all three are needed
	// (and Managed), or the feature is off. ModuleClient fetches; nil means modules.PublicClient().
	Modules     *modules.Set
	ModulesDir  string
	TrustedKeys []modules.TrustedKey
	// CatalogueURL is the optional module index (managed.catalogue_url).
	CatalogueURL string
	ModuleClient *http.Client
	// Profiles holds display names; nil means everyone is shown by sign-in name.
	Profiles *auth.ProfileStore

	// Mentions is who asked to be pinged about which game; DiscordOn says a Discord webhook is set up.
	Mentions  *notify.Mentions
	DiscordOn bool
	// OIDC serves sign-in through other OpenID Connect providers; nil turns it off.
	OIDC *auth.OIDCLogin
	// Settings backs the dashboard's settings dialog (/api/settings).
	Settings *settings.Store

	// Schedules holds the timed starts and stops (nil: none); their times are
	// in TimeZone.
	Schedules *schedule.Store
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
	// Files reads and edits the config files modules declare (admin only). Optional.
	Files *gamefiles.Service
	// Restore puts a chosen backup back (admin only). Optional.
	Restore *restore.Manager
	// Notify reports whether the latest message on each notification channel was delivered; NotifyConfigured
	// says whether any channel is set up. Optional.
	Notify *notify.Status
	// AuditFile is the tamper-evident audit file the export endpoint serves. Optional.
	AuditFile        string
	NotifyConfigured bool
	// Managed backs the Games API (enable games from the dashboard). Optional.
	Managed ManagedGames
	// MetricsToken, when set, serves GET /metrics (Prometheus) to a scraper
	// presenting it as a bearer token. Empty leaves the route out.
	MetricsToken string
	// Crashes adds crash counts to /metrics. Optional.
	Crashes CrashStats
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
	// MaxStreamsPerUser caps one user's share of those streams. Zero means defaultMaxStreamsPerUser.
	MaxStreamsPerUser int
	streamCount       atomic.Int32

	// MaxEventStreams caps concurrent /api/events connections. Zero means
	// defaultMaxEventStreams.
	MaxEventStreams int
	eventStreams    atomic.Int32
	// MaxEventStreamsPerUser caps one user's concurrent /api/events
	// connections. Zero means defaultMaxEventStreamsPerUser.
	MaxEventStreamsPerUser int
	userEventStreams       userStreams
	userLogStreams         userStreams

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

// Routes registers the dashboard, login/logout, and game-control API on
// mux.
func (a *App) Routes(mux *http.ServeMux) {
	if a.MetricsToken != "" {
		mux.HandleFunc("GET /metrics", a.handleMetrics)
	}
	mux.HandleFunc("GET /setup", a.handleSetupPage)
	mux.HandleFunc("POST /setup", a.handleSetup)
	mux.HandleFunc("GET /login", a.handleLoginPage)
	mux.HandleFunc("POST /login", a.Auth.ServeLogin)
	mux.HandleFunc("POST /login/mfa", a.Auth.ServeLoginMFA)
	mux.HandleFunc("POST /login/passkey/begin", a.Auth.ServePasskeyLoginBegin)
	mux.HandleFunc("POST /login/passkey/finish", a.Auth.ServePasskeyLoginFinish)
	mux.HandleFunc("GET "+"/auth/oidc/{id}/start", a.whenOIDC((*auth.OIDCLogin).ServeStart))
	mux.HandleFunc("GET "+"/auth/oidc/{id}/callback", getOnly(a.whenOIDC((*auth.OIDCLogin).ServeCallback)))
	mux.HandleFunc("POST /logout", a.Auth.ServeLogout)
	// Registered always, so the dashboard can turn Google sign-in on and off
	// while the server runs; both answer 404 while it is off.
	if a.Google != nil && a.OIDC != nil {
		google := func(serve func(*auth.OIDCLogin, http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
			return a.whenGoogleActive(func(w http.ResponseWriter, r *http.Request) { serve(a.OIDC, w, r, auth.GoogleProviderID) })
		}
		mux.HandleFunc("GET "+auth.GoogleStartPath, google((*auth.OIDCLogin).ServeStart))
		mux.HandleFunc("GET "+auth.GoogleCallbackPath, getOnly(google((*auth.OIDCLogin).ServeCallback)))
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
	mux.Handle("GET /api/audit/export", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleAuditExport))))
	mux.Handle("GET /api/audit", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleAudit))))
	mux.Handle("GET /api/games/{id}/console", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleConsole))))
	mux.Handle("POST /api/games/{id}/console/action", a.requireAdmin(http.HandlerFunc(a.handleConsoleAction)))
	mux.Handle("POST /api/games/{id}/console/raw", a.requireAdmin(http.HandlerFunc(a.handleConsoleRaw)))
	mux.Handle("POST /api/games/{id}/backup", a.requireAdmin(http.HandlerFunc(a.handleBackup)))
	mux.Handle("POST /api/games/{id}/restore", a.requireAdmin(http.HandlerFunc(a.handleRestore)))
	mux.Handle("GET /api/notify/status", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleNotifyStatus))))
	mux.Handle("GET /api/games/{id}/files", a.requireAdminRead(http.HandlerFunc(a.handleFiles)))
	mux.Handle("GET /api/games/{id}/files/{file}", a.requireAdminRead(http.HandlerFunc(a.handleFileGet)))
	mux.Handle("PUT /api/games/{id}/files/{file}", a.requireAdmin(http.HandlerFunc(a.handleFilePut)))
	mux.Handle("GET /api/games/{id}/files/{file}/history", a.requireAdminRead(http.HandlerFunc(a.handleFileHistory)))
	mux.Handle("GET /api/games/{id}/files/{file}/history/{version}", a.requireAdminRead(http.HandlerFunc(a.handleFileVersion)))
	mux.Handle("GET /api/backups/health", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleBackupsHealth))))
	mux.Handle("GET /api/backups/overview", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleBackupsOverview))))
	mux.Handle("GET /api/games/{id}/backups", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleBackups))))
	mux.Handle("GET /api/host", a.requireSession(http.HandlerFunc(a.handleHost)))
	mux.Handle("GET /api/health", a.requireSession(http.HandlerFunc(a.handleHealth)))
	mux.Handle("GET /api/settings", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleGetSettings))))
	mux.Handle("GET /api/schedules", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleGetSchedules))))
	mux.Handle("PUT /api/schedules", a.requireAdmin(http.HandlerFunc(a.handlePutSchedules)))
	mux.Handle("PUT /api/settings", a.requireAdmin(http.HandlerFunc(a.handlePutSettings)))
	mux.Handle("GET /api/managed/modules", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleManagedModules))))
	mux.Handle("GET /api/managed/configured", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleManagedConfigured))))
	mux.Handle("GET /api/managed/modules/sources", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleModuleSources))))
	mux.Handle("GET /api/managed/modules/catalogue", a.requireAdmin(http.HandlerFunc(a.handleModuleCatalogue)))
	mux.Handle("POST /api/managed/modules/remote/preview", a.requireAdmin(http.HandlerFunc(a.handleRemotePreview)))
	mux.Handle("POST /api/managed/modules/remote/install", a.requireAdmin(http.HandlerFunc(a.handleRemoteInstall)))
	mux.Handle("POST /api/managed/modules/remote/{id}/update/preview", a.requireAdmin(http.HandlerFunc(a.handleRemoteUpdatePreview)))
	mux.Handle("POST /api/managed/modules/remote/{id}/update", a.requireAdmin(http.HandlerFunc(a.handleRemoteUpdate)))
	mux.Handle("POST /api/managed/modules/remote/{id}/remove", a.requireAdmin(http.HandlerFunc(a.handleRemoteRemove)))
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
	mux.Handle("GET /account", a.requireSessionHTML(http.HandlerFunc(a.handleAccountPage)))
	mux.Handle("GET /api/account/profile", a.requireSession(http.HandlerFunc(a.handleGetProfile)))
	mux.Handle("POST /api/account/profile", a.requireSessionAndCSRF(http.HandlerFunc(a.handleSetProfile)))
	mux.Handle("POST /api/account/sign-in-notice/dismiss", a.requireSessionAndCSRF(http.HandlerFunc(a.handleDismissSignIn)))
	mux.Handle("POST /api/account/sessions/revoke", a.requireSessionAndCSRF(http.HandlerFunc(a.handleRevokeSession)))
	mux.Handle("GET /api/account/security", a.requireSession(http.HandlerFunc(a.handleGetSecurity)))
	mux.Handle("GET /api/account/passkeys", a.requireSession(http.HandlerFunc(a.handleListPasskeys)))
	mux.Handle("POST /api/account/passkeys/begin", a.requireSessionAndCSRF(http.HandlerFunc(a.handlePasskeyBegin)))
	mux.Handle("POST /api/account/passkeys/finish", a.requireSessionAndCSRF(http.HandlerFunc(a.handlePasskeyFinish)))
	mux.Handle("POST /api/account/passkeys/remove", a.requireSessionAndCSRF(http.HandlerFunc(a.handleRemovePasskey)))
	mux.Handle("POST /api/account/totp/begin", a.requireSessionAndCSRF(http.HandlerFunc(a.handleTOTPBegin)))
	mux.Handle("GET /api/account/totp/qr", a.requireSession(http.HandlerFunc(a.handleTOTPQR)))
	mux.Handle("POST /api/account/totp/confirm", a.requireSessionAndCSRF(http.HandlerFunc(a.handleTOTPConfirm)))
	mux.Handle("GET /api/account/mentions", a.requireSession(http.HandlerFunc(a.handleGetMentions)))
	mux.Handle("PUT /api/account/mentions", a.requireSessionAndCSRF(http.HandlerFunc(a.handlePutMentions)))
	mux.Handle("POST /api/account/password", a.requireSessionAndCSRF(http.HandlerFunc(a.handleChangePassword)))
	mux.Handle("POST /api/account/totp/disable", a.requireSessionAndCSRF(http.HandlerFunc(a.handleTOTPDisable)))
	mux.Handle("POST /api/account/totp/recovery", a.requireSessionAndCSRF(http.HandlerFunc(a.handleTOTPRecovery)))
	mux.Handle("GET /api/auth/oidc", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleListOIDC))))
	mux.Handle("PUT /api/auth/oidc/{id}", a.requireAdmin(http.HandlerFunc(a.handlePutOIDC)))
	mux.Handle("DELETE /api/auth/oidc/{id}", a.requireAdmin(http.HandlerFunc(a.handleDeleteOIDC)))
	mux.Handle("GET /api/auth/google", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleGetGoogle))))
	mux.Handle("PUT /api/auth/google", a.requireAdmin(http.HandlerFunc(a.handlePutGoogle)))
	mux.Handle("DELETE /api/auth/google", a.requireAdmin(http.HandlerFunc(a.handleDeleteGoogle)))
	mux.Handle("GET /api/auth/password-login", auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, http.HandlerFunc(a.handleGetPasswordLogin))))
	mux.Handle("PUT /api/auth/password-login", a.requireAdmin(http.HandlerFunc(a.handlePutPasswordLogin)))
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

func (a *App) whenGoogleActive(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.Google.Active() {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

func (a *App) requireSession(next http.Handler) http.Handler {
	return auth.RequireSession(a.Auth.Sessions, next)
}

// requireAdmin is requireSessionAndCSRF plus an admin-role check.
func (a *App) requireAdmin(next http.Handler) http.Handler {
	return auth.RequireSession(a.Auth.Sessions, auth.RequireCSRF(auth.RequireAdmin(a.Auth.Sessions, next)))
}

// requireAdminRead is requireAdmin for GET routes, which carry no CSRF token.
func (a *App) requireAdminRead(next http.Handler) http.Handler {
	return auth.RequireSession(a.Auth.Sessions, auth.RequireAdmin(a.Auth.Sessions, next))
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
		session = a.Auth.Sessions.Renew(w, session)
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
	StartError string `json:"start_error,omitempty"`

	// JoinCodes are values the running server printed (a crossplay join
	// code); only sent while the game is online.
	JoinCodes    []games.ConnectSecret `json:"join_codes,omitempty"`
	StartErrorAt int64                 `json:"start_error_at,omitempty"`
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

func (a *App) handleListGames(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.listGames(r))
}

// listGames builds the /api/games body for r's user (admins see raw error
// detail); /api/events sends the same.
func (a *App) listGames(r *http.Request) []gameSummary {
	defs := a.visibleGames(r)
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
		if d.Live != nil && out[i].Status == games.StatusOnline.String() {
			out[i].JoinCodes = d.Live.ConnectValues()
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

// canSee reports whether r's user may see and control game id (see
// auth.UserRecord.Games).
func (a *App) canSee(r *http.Request, id string) bool {
	return a.Auth.Sessions.CanAccessGame(actor(r), id)
}

// visibleGames is the registry's games r's user may see, in registry order.
func (a *App) visibleGames(r *http.Request) []games.GameDef {
	defs := a.Registry.All()
	out := make([]games.GameDef, 0, len(defs))
	for _, d := range defs {
		if a.canSee(r, d.ID) {
			out = append(out, d)
		}
	}
	return out
}

// gameOr404 is the game named in the path, or a 404. A game the user is not
// allowed gets the same 404 as one that does not exist, so its id does not
// leak.
func (a *App) gameOr404(w http.ResponseWriter, r *http.Request) (games.GameDef, bool) {
	id := r.PathValue("id")
	d, ok := a.Registry.Get(id)
	if !ok || !a.canSee(r, d.ID) {
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // signed-in data must not sit in a browser or proxy cache
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
