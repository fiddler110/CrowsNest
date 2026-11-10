// Command crowsnest is a self-hosted controller for game server Docker
// containers: start/stop, live logs, status, and an exclusivity guard that
// keeps at most one game server running at a time.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/backup"
	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/exclusivity"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/history"
	"github.com/fiddler110/crowsnest/internal/idleshutdown"
	"github.com/fiddler110/crowsnest/internal/managed"
	"github.com/fiddler110/crowsnest/internal/modules"
	"github.com/fiddler110/crowsnest/internal/nightshutdown"
	"github.com/fiddler110/crowsnest/internal/notify"
	"github.com/fiddler110/crowsnest/internal/playerwatch"
	"github.com/fiddler110/crowsnest/internal/settings"
	"github.com/fiddler110/crowsnest/internal/statehub"
	"github.com/fiddler110/crowsnest/internal/web"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "serve":
		if err := serve(); err != nil {
			log.Fatal(err)
		}
	case "execguard":
		if err := runExecGuard(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "guard":
		if err := runGuard(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	case "render":
		if err := runRender(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	case "module":
		if len(os.Args) < 3 || os.Args[2] != "check" {
			fmt.Fprintln(os.Stderr, "usage: crowsnest module check <module.yaml|dir> [--log container.log]")
			os.Exit(2)
		}
		os.Exit(runModuleCheck(os.Args[3:], os.Stdout))
	case "doctor":
		cfg, err := config.Load(configPath())
		if err != nil {
			fmt.Fprintln(os.Stderr, "FAIL  config does not load:", err)
			os.Exit(1)
		}
		os.Exit(runDoctor(cfg, &dockerctl.Client{Host: cfg.Server.DockerHost}, os.Stdout))
	case "healthcheck":
		os.Exit(healthcheck())
	case "set-password":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: crowsnest set-password <username>")
			os.Exit(2)
		}
		if err := setPassword(os.Args[2]); err != nil {
			log.Fatal(err)
		}
	case "revoke-sessions":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: crowsnest revoke-sessions <username>")
			os.Exit(2)
		}
		if err := revokeSessions(os.Args[2]); err != nil {
			log.Fatal(err)
		}
	case "set-role":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: crowsnest set-role <username> <admin|player>")
			os.Exit(2)
		}
		if err := setRole(os.Args[2], os.Args[3]); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (want: serve, doctor, module, execguard, guard, healthcheck, set-password, set-role, revoke-sessions)\n", cmd)
		os.Exit(2)
	}
}

// newMux builds the HTTP route table: the always-present healthcheck plus,
// when app is non-nil, the game-control API. app is nil only in the
// healthz-only test case; serve() always supplies one.
func newMux(app *web.App) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	if app != nil {
		app.Routes(mux)
	}
	return mux
}

// configPath returns the config.yaml location: $CROWSNEST_CONFIG if set,
// else the container runtime default under /app (see Dockerfile WORKDIR).
func configPath() string {
	if p := os.Getenv("CROWSNEST_CONFIG"); p != "" {
		return p
	}
	return "/app/config.yaml"
}

func serve() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(configPath())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	docker := &dockerctl.Client{Host: cfg.Server.DockerHost}
	mods, err := modules.ForConfig(cfg, log.Printf)
	if err != nil {
		return fmt.Errorf("load modules: %w", err)
	}
	defs, runners := mods.Build(cfg, docker)
	registry, err := games.NewRegistry(defs)
	if err != nil {
		return fmt.Errorf("build game registry: %w", err)
	}
	for _, d := range defs {
		if !games.CanCountPlayers(d) {
			log.Printf("warning: %s has no player counter configured — idle and night shutdown will never stop it", d.ID)
		}
	}
	for _, r := range runners {
		go r.Run(ctx)
	}

	userStore, err := auth.NewUserStore(cfg.UsersFile)
	if err != nil {
		return fmt.Errorf("load users: %w", err)
	}
	go userStore.Watch(ctx, 3*time.Second)
	setup := &auth.Setup{Store: userStore, CodeFile: filepath.Join(filepath.Dir(cfg.Server.SessionSecretFile), "setup-token")}
	if users := userStore.Snapshot(); len(users) == 0 {
		if code, _, err := setup.Code(); err != nil {
			log.Printf("warning: no users configured yet in %s and no setup code could be made (%v) — run `crowsnest set-password <username>` to create one", cfg.UsersFile, err)
		} else {
			log.Printf("setup: no users yet. Open /setup in a browser and enter the setup code %s (also saved in %s), or run `crowsnest set-password <username>`", code, setup.CodeFile)
		}
	} else if !hasAdmin(users) {
		log.Printf("warning: no admin in %s; a Google-only user with no role is a player — run `crowsnest set-role <username> admin`", cfg.UsersFile)
	}
	secret, err := auth.LoadOrCreateSecret(cfg.Server.SessionSecretFile)
	if err != nil {
		return fmt.Errorf("load session secret: %w", err)
	}
	trustedProxies, err := auth.ParseTrustedProxies(cfg.Server.TrustedProxies)
	if err != nil {
		return fmt.Errorf("parse trusted proxies: %w", err)
	}
	loginLimiter := auth.NewLimiter(10, 5*time.Minute)
	go loginLimiter.RunPruner(ctx, 10*time.Minute)
	sessions := auth.NewSessionManager(secret, auth.DefaultSessionTTL)
	sessions.Store = userStore // per-user revocation; follows `revoke-sessions` live
	authSvc := &auth.Service{
		Store:                userStore,
		Sessions:             sessions,
		LoginLimiter:         loginLimiter,
		TrustedProxies:       trustedProxies,
		SecureCookies:        cfg.Server.SecureCookies,
		DisablePasswordLogin: !cfg.Auth.PasswordLoginEnabled(),
	}
	google, err := googleLogin(cfg, authSvc)
	if err != nil {
		return err
	}
	if google != nil {
		password := "enabled"
		if authSvc.DisablePasswordLogin {
			password = "disabled"
		}
		log.Printf("auth: Google sign-in enabled; password sign-in %s", password)
	}
	if google != nil {
		google.Store = userStore
	}
	sessions.Allowed = sessionAllowed(userStore.Snapshot, google, authSvc.DisablePasswordLogin)

	templates, err := web.LoadTemplates()
	if err != nil {
		return fmt.Errorf("load templates: %w", err)
	}

	settingsStore, err := settings.New(settings.Values{
		IdleEnabled:    cfg.IdleShutdown.Enabled,
		IdleMinutes:    cfg.IdleShutdown.IdleMinutes,
		NightEnabled:   cfg.NightShutdown.Enabled,
		NightStartHour: cfg.NightShutdown.StartHour,
		NightEndHour:   cfg.NightShutdown.EndHour,
		MaxActiveGames: cfg.Server.MaxActiveGames,
		AutoUpdate:     cfg.Server.AutoUpdate,
	}, cfg.Server.SettingsFile)
	if err != nil {
		return fmt.Errorf("load settings: %w", err)
	}
	log.Printf("settings: %+v (changes saved to %s)", settingsStore.Get(), cfg.Server.SettingsFile)

	activity, err := history.Open(cfg.Server.HistoryFile, time.Duration(cfg.Server.HistoryRetentionDays)*24*time.Hour)
	if err != nil {
		return fmt.Errorf("open activity log: %w", err)
	}
	go activity.RunPruner(ctx)

	exclusivityMgr := exclusivity.NewManager(registry, docker)
	exclusivityMgr.History = activity
	backups := &backup.Manager{Docker: docker, History: activity, BaseContext: ctx}
	exclusivityMgr.Backups = backups
	exclusivityMgr.MaxActiveFunc = func() int { return settingsStore.Get().MaxActiveGames }
	if budget := newMemoryBudget(cfg, registry); budget != nil {
		exclusivityMgr.Memory = budget
		go sampleMemory(ctx, budget, docker, registry)
	}
	exclusivityMgr.AutoUpdate = func() bool { return settingsStore.Get().AutoUpdate }
	// Background starts (compose pull/up) belong to the process, not to the
	// HTTP request that asked for them; shutdown cancels them.
	exclusivityMgr.BaseContext = ctx

	// One observer per game feeds the dashboard, its live stream, player
	// announcements and both auto-stop loops. Every start/stop transition
	// pokes it, so the change shows at once.
	hub := statehub.New(registry)
	hub.Busy = func(id string) bool { return exclusivityMgr.Starting(id) || exclusivityMgr.Stopping(id) }
	exclusivityMgr.OnChange = func(id string) { hub.Poke(id); hub.Signal() }
	go hub.Run(ctx)

	app := &web.App{
		Hub:         hub,
		Registry:    registry,
		Docker:      docker,
		Exclusivity: exclusivityMgr,
		Auth:        authSvc,
		Setup:       setup,
		Google:      google,
		Settings:    settingsStore,
		TimeZone:    cfg.Server.TZ,
		History:     activity,
		HostPaths:   cfg.Server.HostDiskPaths,
		Backups:     backups,
		Templates:   templates,
	}

	if cfg.Managed.Dir != "" {
		if cfg.Managed.PolicyEditable {
			log.Printf("warning: managed.policy_editable is on: the panel can rewrite %s (it may only tighten it, but it can still remove limits it was given)", cfg.Managed.PolicyFile)
		}
		mgr := &managed.Manager{
			Dir: cfg.Managed.Dir, PolicyFile: cfg.Managed.PolicyFile, PolicyEditable: cfg.Managed.PolicyEditable, Platform: modules.PlatformFrom(cfg.Platform),
			Modules: mods, Config: cfg, Docker: docker, Wire: docker, Registry: registry,
			Busy: func(id string) bool { return exclusivityMgr.Starting(id) || exclusivityMgr.Stopping(id) },
		}
		if err := mgr.Restore(ctx); err != nil {
			return fmt.Errorf("managed games: %w", err)
		}
		app.Managed = mgr
		log.Printf("managed games: enabled from the dashboard, state in %s, policy %s", cfg.Managed.Dir, cfg.Managed.PolicyFile)
	}

	var discordNotifier *notify.Discord
	if cfg.Notifications.DiscordWebhookURLEnv != "" {
		discordNotifier = &notify.Discord{WebhookURL: os.Getenv(cfg.Notifications.DiscordWebhookURLEnv)}
		if discordNotifier.WebhookURL == "" {
			log.Printf("notify: %s is not set — Discord notifications disabled", cfg.Notifications.DiscordWebhookURLEnv)
		}
	} else {
		discordNotifier = &notify.Discord{} // inert zero value; Notify becomes a no-op
	}

	// Manual starts/stops/switches and failed starts notify too. Auto-stops
	// call Stop without an actor, so they don't double up with idle/night's
	// own messages.
	exclusivityMgr.Notifier = discordNotifier
	backups.Notifier = discordNotifier

	// Both auto-stop loops always run and re-read the settings store each
	// tick, so toggling or retuning them from the dashboard applies at once.
	idle := idleshutdown.New(
		registry,
		exclusivityMgr,
		time.Duration(settingsStore.Get().IdleMinutes)*time.Minute,
		time.Duration(cfg.IdleShutdown.CheckIntervalSeconds)*time.Second,
	)
	idle.Settings = func() (bool, time.Duration) {
		v := settingsStore.Get()
		return v.IdleEnabled, time.Duration(v.IdleMinutes) * time.Minute
	}
	idle.Notifier = discordNotifier
	idle.History = activity
	idle.Hub = hub
	app.IdleTimer = idle
	go idle.Run(ctx)

	loc, err := cfg.Server.Location()
	if err != nil {
		return fmt.Errorf("night shutdown: %w", err)
	}
	night := nightshutdown.New(
		registry,
		exclusivityMgr,
		settingsStore.Get().NightStartHour,
		settingsStore.Get().NightEndHour,
		time.Duration(cfg.NightShutdown.CheckIntervalMinutes)*time.Minute,
		loc,
	)
	night.Settings = func() (bool, int, int) {
		v := settingsStore.Get()
		return v.NightEnabled, v.NightStartHour, v.NightEndHour
	}
	night.Notifier = discordNotifier
	night.History = activity
	night.Hub = hub
	night.StartedAt = docker.StartedAt
	night.MinUptime = time.Duration(cfg.NightShutdown.MinUptimeMinutes) * time.Minute
	go night.Run(ctx)

	// Always runs: it feeds the activity log's playtime totals, and only posts
	// join/leave messages when a webhook is set and player_events isn't off.
	var joinLeave playerwatch.Notifier
	if discordNotifier.WebhookURL != "" && cfg.Notifications.PlayerEventsEnabled() {
		joinLeave = discordNotifier
	}
	watcher := playerwatch.New(registry, joinLeave, 30*time.Second)
	watcher.History = activity
	watcher.Hub = hub // re-checks on every hub change
	go watcher.Run(ctx)

	// Header/idle timeouts bound slow or idle clients (slowloris). No
	// Read/WriteTimeout: the log and startup-progress SSE streams stay open
	// for as long as the dashboard is watching.
	srv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           auth.SecurityHeaders(cfg.Server.SecureCookies, newMux(app)),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Printf("crowsnest listening on %s", cfg.Server.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}

	stop()
	log.Printf("shutting down (signal received)")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	// Let cancelled background starts unwind (and report) before exiting. A
	// stop already under way is not interrupted: it runs on the docker
	// daemon, and the process only waits briefly for it.
	waited := make(chan struct{})
	go func() { exclusivityMgr.Wait(); backups.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(10 * time.Second):
		log.Printf("shutdown: background operations still running; exiting anyway")
	}
	return <-serveErr
}

// setPassword implements `crowsnest set-password <username>`: reads a
// password from stdin (not hidden — pipe it in, e.g. from a password
// manager, rather than typing it where it might echo to the terminal) and
// upserts its bcrypt hash into the configured users file.
func setPassword(username string) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Password for %s: ", username)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("read password: %w", err)
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := auth.SetUserHash(cfg.UsersFile, username, hash); err != nil {
		return err
	}
	fmt.Printf("Password set for %s in %s\n", strings.ToLower(username), cfg.UsersFile)
	return nil
}

// revokeSessions implements `crowsnest revoke-sessions <username>`: marks
// every session currently issued for username invalid, forcing a fresh
// login on every device — e.g. after a lost/compromised device, or when
// offboarding a user. Like set-password, this edits the users file but
// is picked up by a running server within a few seconds.
func revokeSessions(username string) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	allowNew := googleAllowed(cfg, username)
	if err := auth.RevokeSessions(cfg.UsersFile, username, allowNew); err != nil {
		return err
	}
	fmt.Printf("Revoked sessions for %s in %s — a running server picks this up within a few seconds\n", strings.ToLower(username), cfg.UsersFile)
	return nil
}

// googleAllowed reports whether username is on the Google sign-in allowlist.
// Such a user may have no users-file entry yet (no password), so commands that
// only write a marker for them (revoke-sessions, set-role) allow creating one;
// a typo'd name still fails.
func googleAllowed(cfg *config.Config, username string) bool {
	g := cfg.Auth.Google
	if g == nil {
		return false
	}
	users, err := auth.ParseGoogleUsers(os.Getenv(g.UsersEnv))
	if err != nil {
		return false
	}
	for _, name := range users {
		if name == strings.ToLower(username) {
			return true
		}
	}
	return false
}

// setRole implements `crowsnest set-role <username> <admin|player>`. Admins
// can change settings; players can start, stop and switch games. A running
// server picks the change up within a few seconds.
func setRole(username, roleName string) error {
	role, err := auth.ParseRole(roleName)
	if err != nil {
		return err
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := auth.SetRole(cfg.UsersFile, username, role, googleAllowed(cfg, username)); err != nil {
		return err
	}
	fmt.Printf("%s is now %s (a running server picks this up within a few seconds)\n", strings.ToLower(username), role)
	return nil
}

// defaultHealthcheckAddr is used when config.yaml can't be loaded (e.g.
// missing/unreadable) — matches config's own default server.addr, so
// healthcheck() and serve() agree on where to look absent any config.
const defaultHealthcheckAddr = "localhost:5000"

// healthcheckAddr converts a server.addr value (e.g. ":5000",
// "0.0.0.0:5000", "127.0.0.1:8080") into a loopback host:port that
// healthcheck() can dial from inside the same container. Falls back to
// defaultHealthcheckAddr if addr can't be parsed as a host:port.
func healthcheckAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return defaultHealthcheckAddr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

// healthcheck is invoked as `crowsnest healthcheck` from the Dockerfile's
// HEALTHCHECK instruction — an in-process HTTP GET, avoiding a curl
// dependency in the runtime image. Reads config.yaml to find the port serve()
// actually bound (server.addr defaults to :5000, but is user-configurable),
// so this stays correct if that's ever changed. Returns a process exit code
// (0 = healthy).
func healthcheck() int {
	addr := defaultHealthcheckAddr
	if cfg, err := config.Load(configPath()); err == nil {
		addr = healthcheckAddr(cfg.Server.Addr)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthz returned %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

// sessionAllowed reports whether a session's user may still be signed in: a
// password user while password sign-in is on, or a name on the Google
// allowlist. Sessions are stateless, so this is what ends a removed user's
// session (within seconds, as the users file is watched) instead of letting
// it run out its TTL.
// hasAdmin reports whether any user in the file resolves to the admin role.
func hasAdmin(users auth.Users) bool {
	for _, u := range users {
		if u.EffectiveRole() == auth.RoleAdmin {
			return true
		}
	}
	return false
}

func sessionAllowed(users func() auth.Users, google *auth.GoogleLogin, passwordDisabled bool) func(string) bool {
	return func(name string) bool {
		if google != nil {
			if google.Allows(name) {
				return true
			}
		}
		if passwordDisabled {
			return false
		}
		rec, ok := users()[name]
		return ok && rec.Hash != ""
	}
}

// googleLogin builds Google sign-in from config and the environment, or
// returns nil when auth.google isn't configured. Missing or malformed values
// are a startup error rather than a silently disabled login.
func googleLogin(cfg *config.Config, svc *auth.Service) (*auth.GoogleLogin, error) {
	g := cfg.Auth.Google
	if g == nil {
		return nil, nil
	}
	clientID, secret := os.Getenv(g.ClientIDEnv), os.Getenv(g.ClientSecretEnv)
	if clientID == "" || secret == "" {
		return nil, fmt.Errorf("auth.google: %s and %s must both be set", g.ClientIDEnv, g.ClientSecretEnv)
	}
	users, err := auth.ParseGoogleUsers(os.Getenv(g.UsersEnv))
	if err != nil {
		return nil, fmt.Errorf("auth.google: %s: %w", g.UsersEnv, err)
	}
	return &auth.GoogleLogin{
		ClientID:     clientID,
		ClientSecret: secret,
		RedirectURL:  g.RedirectURL,
		Users:        users,
		Service:      svc,
	}, nil
}
