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
	"github.com/fiddler110/crowsnest/internal/crashwatch"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/exclusivity"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/history"
	"github.com/fiddler110/crowsnest/internal/idleshutdown"
	"github.com/fiddler110/crowsnest/internal/managed"
	"github.com/fiddler110/crowsnest/internal/mfa"
	"github.com/fiddler110/crowsnest/internal/modules"
	"github.com/fiddler110/crowsnest/internal/nightshutdown"
	"github.com/fiddler110/crowsnest/internal/notify"
	"github.com/fiddler110/crowsnest/internal/playerwatch"
	"github.com/fiddler110/crowsnest/internal/restore"
	"github.com/fiddler110/crowsnest/internal/settings"
	"github.com/fiddler110/crowsnest/internal/statehub"
	"github.com/fiddler110/crowsnest/internal/vault"
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
		if len(os.Args) >= 3 && os.Args[2] == "check" {
			os.Exit(runModuleCheck(os.Args[3:], os.Stdout))
		}
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, moduleUsage)
			os.Exit(2)
		}
		cfg, err := config.Load(configPath())
		if err != nil {
			fmt.Fprintln(os.Stderr, "FAIL  config does not load:", err)
			os.Exit(1)
		}
		t := &moduleTool{dir: cfg.ModulesDir, in: os.Stdin, out: os.Stdout}
		os.Exit(t.run(os.Args[2:]))
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
	case "clear-password":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: crowsnest clear-password <username>")
			os.Exit(2)
		}
		if err := clearPassword(os.Args[2]); err != nil {
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
	case "enable-password-login":
		if err := enablePasswordLogin(); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (want: serve, doctor, module, execguard, guard, healthcheck, set-password, set-role, revoke-sessions, enable-password-login)\n", cmd)
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

	vlt, err := vault.New(os.Getenv(vault.EnvKey), filepath.Join(filepath.Dir(cfg.Server.SessionSecretFile), "master.key"))
	if err != nil {
		return err
	}
	if vlt.Source == vault.SourceFile {
		log.Printf("warning: secrets on disk are encrypted with a key kept in %s, next to the data; set %s (from outside the data volume) so a copy of the volume alone can't open them",
			filepath.Join(filepath.Dir(cfg.Server.SessionSecretFile), "master.key"), vault.EnvKey)
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
	importLegacyGoogleUsers(cfg, userStore)
	secret, err := auth.LoadOrCreateSealedSecret(cfg.Server.SessionSecretFile, vlt)
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
	envGoogle, err := googleLogin(cfg)
	if err != nil {
		return err
	}
	// The login object always exists, so the dashboard can switch Google on
	// or off while the server runs; the routes answer 404 while it is off.
	google := &auth.GoogleLogin{Store: userStore}
	fallback := auth.GoogleSettings{}
	if envGoogle != nil {
		fallback = auth.GoogleSettings{Enabled: true, ClientID: envGoogle.ClientID, ClientSecret: envGoogle.ClientSecret, RedirectURL: envGoogle.RedirectURL}
	}
	googleConf, err := auth.NewGoogleConfStore(
		filepath.Join(filepath.Dir(cfg.Server.SettingsFile), "auth.json"),
		vlt, fallback)
	if err != nil {
		log.Printf("warning: dashboard Google sign-in settings ignored: %v", err)
	}
	if googleConf == nil {
		return fmt.Errorf("google sign-in settings: %w", err)
	}
	googleConf.Apply(google)
	authPrefs, err := auth.NewPrefsStore(filepath.Join(filepath.Dir(cfg.Server.SettingsFile), "auth-prefs.json"))
	if err != nil {
		return err
	}
	authSvc.SetPasswordLoginOverride(authPrefs.PasswordLogin())
	mfaStore, err := mfa.NewStore(filepath.Join(filepath.Dir(cfg.Server.SettingsFile), "mfa.json"), vlt)
	if err != nil {
		return err
	}
	authSvc.MFA = mfaStore
	oidcStore, err := auth.NewOIDCStore(filepath.Join(filepath.Dir(cfg.Server.SettingsFile), "oidc.json"), vlt)
	if err != nil {
		log.Printf("warning: %v", err)
	}
	if oidcStore == nil {
		return fmt.Errorf("sign-in providers: %w", err)
	}
	oidcLogin := &auth.OIDCLogin{Store: oidcStore, Google: google, Users: userStore, Service: authSvc}
	if _, src := googleConf.Effective(); google.Active() {
		password := "enabled"
		if authSvc.PasswordLoginDisabled() {
			password = "disabled"
		}
		log.Printf("auth: Google sign-in enabled (settings from %s); password sign-in %s", src, password)
	}
	sessions.Allowed = sessionAllowed(userStore.Snapshot, google, oidcLogin, authSvc.PasswordLoginDisabled)

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

	var backupRoot *backup.Root
	if cfg.Platform.BackupsRoot != "" {
		mode, _ := cfg.Platform.DirMode() // validated when the config loads
		backupRoot = &backup.Root{
			Mount: cfg.Platform.BackupsMount, Mode: mode,
			StateFile:  filepath.Join(filepath.Dir(cfg.Server.SettingsFile), "backups-root"),
			ConfirmNew: cfg.Platform.BackupsConfirmNew,
		}
		if err := backupRoot.Verify(); err != nil {
			log.Printf("warning: %v (backups to the shared folder are refused until this is fixed)", err)
		}
	}
	exclusivityMgr := exclusivity.NewManager(registry, docker)
	exclusivityMgr.History = activity
	backups := &backup.Manager{Docker: docker, Root: backupRoot, History: activity, BaseContext: ctx}
	exclusivityMgr.Backups = backups
	exclusivityMgr.MaxActiveFunc = func() int { return settingsStore.Get().MaxActiveGames }
	exclusivityMgr.CooldownFunc = func(id string) (time.Duration, bool) {
		secs, ok := settingsStore.Get().CooldownOverride(id)
		return time.Duration(secs) * time.Second, ok
	}
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

	var metricsToken string
	if env := cfg.Server.MetricsTokenEnv; env != "" {
		if metricsToken = os.Getenv(env); metricsToken == "" {
			log.Printf("warning: server.metrics_token_env names %s, which is not set: /metrics stays off", env)
		}
	}

	app := &web.App{
		MetricsToken: metricsToken,
		Hub:          hub,
		Registry:     registry,
		Docker:       docker,
		Exclusivity:  exclusivityMgr,
		Auth:         authSvc,
		Setup:        setup,
		Google:       google,
		GoogleConf:   googleConf,
		AuthPrefs:    authPrefs,
		MFA:          mfaStore,
		OIDC:         oidcLogin,
		Settings:     settingsStore,
		TimeZone:     cfg.Server.TZ,
		History:      activity,
		HostPaths:    cfg.Server.HostDiskPaths,
		Backups:      backups,
		Templates:    templates,
	}

	var managedMgr *managed.Manager
	if cfg.Managed.Dir != "" {
		if cfg.Managed.PolicyEditable {
			log.Printf("warning: managed.policy_editable is on: the panel can rewrite %s (it may only tighten it, but it can still remove limits it was given)", cfg.Managed.PolicyFile)
		}
		mgr := &managed.Manager{
			Vault:   vlt,
			Backups: backupRoot,
			Dir:     cfg.Managed.Dir, PolicyFile: cfg.Managed.PolicyFile, PolicyEditable: cfg.Managed.PolicyEditable, Platform: modules.PlatformFrom(cfg.Platform),
			Modules: mods, Config: cfg, Docker: docker, Wire: docker, Registry: registry,
			Busy: func(id string) bool { return exclusivityMgr.Starting(id) || exclusivityMgr.Stopping(id) },
		}
		if err := mgr.Restore(ctx); err != nil {
			return fmt.Errorf("managed games: %w", err)
		}
		mgr.RunHelper = func(ctx context.Context, spec dockerctl.CreateSpec) error {
			return docker.RunOnce(ctx, spec, 10*time.Minute, time.Second)
		}
		app.Managed = mgr
		managedMgr = mgr
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
	if managedMgr != nil && backupRoot != nil {
		app.Restore = &restore.Manager{
			Docker: docker, Control: exclusivityMgr, Backups: backups, Spec: managedMgr.RestoreSpec,
			History: activity, Notifier: discordNotifier, BaseContext: ctx,
		}
	}
	// Re-check the shared backups folder every minute: a drive that disappears
	// or fills is announced once, and backups are refused until it is back.
	go backups.RunMonitor(ctx, time.Minute, registry.All)

	crashes := crashwatch.New(registry, docker)
	crashes.Crashes = cfg.CrashLoop.Crashes
	crashes.Window = time.Duration(cfg.CrashLoop.WindowMinutes) * time.Minute
	crashes.History = activity
	crashes.Notifier = discordNotifier
	app.Crashes = crashes
	if cfg.CrashLoop.Enabled == nil || *cfg.CrashLoop.Enabled {
		go crashes.Run(ctx)
	}

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
	idle.GameIdle = func(id string) (time.Duration, bool) {
		v := settingsStore.Get()
		if g, ok := v.PerGame[id]; ok && g.IdleMinutes != nil {
			return time.Duration(*g.IdleMinutes) * time.Minute, true
		}
		return 0, false
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
	night.GameOverride = func(id string) (bool, bool) { return settingsStore.Get().NightOverride(id) }
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

// clearPassword implements `crowsnest clear-password <username>`: drops the stored
// password hash of a user who signs in with Google, so a leaked users file or an
// old password can't be used. It refuses unless Google sign-in is set up for them.
// Existing sessions are revoked too, since they were issued on the password.
func clearPassword(username string) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	other := cfg.Auth.Google != nil
	if other {
		users, err := auth.LoadUsers(cfg.UsersFile)
		if err != nil {
			return err
		}
		other = users[strings.ToLower(username)].GoogleEmail != ""
	}
	if err := auth.ClearPasswordHash(cfg.UsersFile, username, other); err != nil {
		return err
	}
	if err := auth.RevokeSessions(cfg.UsersFile, username, true); err != nil {
		return err
	}
	fmt.Printf("Cleared the password for %s; they sign in with Google now (role kept, sessions revoked)\n", strings.ToLower(username))
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
	if err := auth.RevokeSessions(cfg.UsersFile, username, false); err != nil {
		return err
	}
	fmt.Printf("Revoked sessions for %s in %s — a running server picks this up within a few seconds\n", strings.ToLower(username), cfg.UsersFile)
	return nil
}

// enablePasswordLogin is the way back in when password sign-in was turned off
// from the dashboard and the other sign-in method stopped working. It saves
// "password sign-in on" where the dashboard keeps its choice, which wins over
// config.yaml; restart the server for it to apply.
func enablePasswordLogin() error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	store, err := auth.NewPrefsStore(filepath.Join(filepath.Dir(cfg.Server.SettingsFile), "auth-prefs.json"))
	if err != nil {
		return err
	}
	on := true
	if err := store.SetPasswordLogin(&on); err != nil {
		return err
	}
	fmt.Println("Password sign-in is on again. Restart CrowsNest for it to apply.")
	return nil
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
	if err := auth.SetRole(cfg.UsersFile, username, role, false); err != nil {
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

func sessionAllowed(users func() auth.Users, google *auth.GoogleLogin, oidc *auth.OIDCLogin, passwordDisabled func() bool) func(string) bool {
	return func(name string) bool {
		if google != nil {
			if google.Allows(name) {
				return true
			}
		}
		if oidc.Allows(name) {
			return true
		}
		if passwordDisabled() {
			return false
		}
		rec, ok := users()[name]
		return ok && rec.Hash != ""
	}
}

// googleLogin builds Google sign-in from config and the environment, or
// returns nil when auth.google isn't configured. Missing or malformed values
// are a startup error rather than a silently disabled login.
func googleLogin(cfg *config.Config) (*auth.GoogleLogin, error) {
	g := cfg.Auth.Google
	if g == nil {
		return nil, nil
	}
	clientID, secret := os.Getenv(g.ClientIDEnv), os.Getenv(g.ClientSecretEnv)
	if clientID == "" || secret == "" {
		return nil, fmt.Errorf("auth.google: %s and %s must both be set", g.ClientIDEnv, g.ClientSecretEnv)
	}
	return &auth.GoogleLogin{
		ClientID:     clientID,
		ClientSecret: secret,
		RedirectURL:  g.RedirectURL,
	}, nil
}

// importLegacyGoogleUsers carries the old CROWSNEST_GOOGLE_USERS allowlist
// (name=email pairs) into the users file, once, so the dashboard is the only
// place the list is kept from then on. A marker file records that it ran, so
// an email removed in the dashboard doesn't come back at the next start. While
// the users file is still empty (first-run setup not done) it waits.
func importLegacyGoogleUsers(cfg *config.Config, userStore *auth.UserStore) {
	g := cfg.Auth.Google
	if g == nil {
		return
	}
	gu, err := auth.ParseGoogleUsers(os.Getenv(g.UsersEnv))
	if err != nil {
		return // unset, empty or malformed: nothing to import
	}
	marker := filepath.Join(filepath.Dir(cfg.Server.SettingsFile), "google-users-imported")
	if _, err := os.Stat(marker); err == nil {
		log.Printf("notice: %s is ignored; Google sign-in is allowed per user under Settings, Users (imported earlier)", g.UsersEnv)
		return
	}
	if all, err := auth.LoadUsers(cfg.UsersFile); err == nil && len(all) == 0 {
		log.Printf("notice: %s will be imported into the users file once the first admin exists (restart after setup)", g.UsersEnv)
		return
	}
	imported, skipped, err := auth.ImportGoogleEmails(cfg.UsersFile, gu)
	if err != nil {
		log.Printf("warning: could not import %s into %s: %v", g.UsersEnv, cfg.UsersFile, err)
		return
	}
	if len(imported) > 0 {
		log.Printf("auth: imported Google emails from %s into %s: %s. Manage them under Settings, Users from now on; the variable can be removed", g.UsersEnv, cfg.UsersFile, strings.Join(imported, ", "))
		_, _ = userStore.Reload()
	}
	for _, e := range skipped {
		log.Printf("warning: %s not imported: that user already has a different Google email (one per user)", e)
	}
	if err := os.WriteFile(marker, []byte("done\n"), 0o600); err != nil {
		log.Printf("warning: could not write %s: %v", marker, err)
	}
}
