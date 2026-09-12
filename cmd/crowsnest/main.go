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
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/exclusivity"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/games/palworld"
	"github.com/fiddler110/crowsnest/internal/games/valheim"
	"github.com/fiddler110/crowsnest/internal/games/windrose"
	"github.com/fiddler110/crowsnest/internal/idleshutdown"
	"github.com/fiddler110/crowsnest/internal/nightshutdown"
	"github.com/fiddler110/crowsnest/internal/notify"
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
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (want: serve, healthcheck, set-password)\n", cmd)
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
		w.Write([]byte("ok"))
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
	defs := games.FromConfig(cfg.Games, docker)
	var valheimTrackers []*valheim.Tracker
	for i, d := range defs {
		// cfg.Games[i] lines up 1:1 with defs[i]: FromConfig builds defs by
		// iterating cfg.Games in order without filtering or reordering.
		switch d.ID {
		case "windrose":
			// Real status/startup detection (a direct port of the original
			// Python CrowsNest's log-marker grep) plus, when configured,
			// the Windrose+ HTTP/RCON integration for player count and the
			// rich info panel — see docs/implementation-plan.md phases 7
			// and 10.
			defs[i].Status = &windrose.StatusChecker{Docker: docker}
			defs[i].Startup = windrose.Startup
			if wc := cfg.Games[i].Windrose; wc != nil {
				client := &windrose.Client{
					BaseURL:       wc.HTTPAPIURL,
					Password:      os.Getenv(wc.RCONPasswordEnv),
					Docker:        docker,
					ContainerName: d.ContainerName,
				}
				defs[i].Players = client
				defs[i].Info = client
			}
		case "palworld":
			// Palworld's dedicated server REST API doubles as both status
			// probe (reachable == online) and player counter — see
			// docs/implementation-plan.md phase 10. Not yet exercised
			// against a real running server.
			if pc := cfg.Games[i].Palworld; pc != nil {
				client := &palworld.Client{
					BaseURL:  pc.RESTAPIURL,
					User:     pc.RESTAPIUser,
					Password: os.Getenv(pc.RESTAPIPasswordEnv),
					Docker:   docker,
				}
				defs[i].Status = client
				defs[i].Players = client
			}
		case "valheim":
			// No first-party API: player count comes from tailing the
			// container's own log output for join/leave markers — see
			// docs/implementation-plan.md phase 10. Not yet exercised
			// against a real running server.
			tracker := valheim.NewTracker(docker, d.ContainerName)
			defs[i].Players = tracker
			valheimTrackers = append(valheimTrackers, tracker)
		}
	}
	registry, err := games.NewRegistry(defs)
	if err != nil {
		return fmt.Errorf("build game registry: %w", err)
	}
	for _, tr := range valheimTrackers {
		go tr.Run(ctx)
	}

	users, err := auth.LoadUsers(cfg.UsersFile)
	if err != nil {
		return fmt.Errorf("load users: %w", err)
	}
	if len(users) == 0 {
		log.Printf("warning: no users configured yet in %s — run `crowsnest set-password <username>` to create one", cfg.UsersFile)
	}
	secret, err := auth.LoadOrCreateSecret(cfg.Server.SessionSecretFile)
	if err != nil {
		return fmt.Errorf("load session secret: %w", err)
	}
	trustedProxies, err := auth.ParseTrustedProxies(cfg.Server.TrustedProxies)
	if err != nil {
		return fmt.Errorf("parse trusted proxies: %w", err)
	}
	authSvc := &auth.Service{
		Users:          users,
		Sessions:       auth.NewSessionManager(secret, auth.DefaultSessionTTL),
		LoginLimiter:   auth.NewLimiter(10, 5*time.Minute),
		TrustedProxies: trustedProxies,
		SecureCookies:  cfg.Server.SecureCookies,
	}

	templates, err := web.LoadTemplates()
	if err != nil {
		return fmt.Errorf("load templates: %w", err)
	}

	exclusivityMgr := exclusivity.NewManager(registry, docker)
	app := &web.App{
		Registry:    registry,
		Docker:      docker,
		Exclusivity: exclusivityMgr,
		Auth:        authSvc,
		Templates:   templates,
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

	if cfg.IdleShutdown.Enabled {
		idle := idleshutdown.New(
			registry,
			exclusivityMgr,
			time.Duration(cfg.IdleShutdown.IdleMinutes)*time.Minute,
			time.Duration(cfg.IdleShutdown.CheckIntervalSeconds)*time.Second,
		)
		idle.Notifier = discordNotifier
		go idle.Run(ctx)
		log.Printf("idleshutdown: enabled, stopping games after %dm with no players (checked every %ds)",
			cfg.IdleShutdown.IdleMinutes, cfg.IdleShutdown.CheckIntervalSeconds)
	} else {
		log.Printf("idleshutdown: disabled via config")
	}

	if cfg.NightShutdown.Enabled {
		loc, err := cfg.Server.Location()
		if err != nil {
			return fmt.Errorf("night shutdown: %w", err)
		}
		night := nightshutdown.New(
			registry,
			exclusivityMgr,
			cfg.NightShutdown.StartHour,
			cfg.NightShutdown.EndHour,
			time.Duration(cfg.NightShutdown.CheckIntervalMinutes)*time.Minute,
			loc,
		)
		night.Notifier = discordNotifier
		go night.Run(ctx)
		log.Printf("nightshutdown: enabled, stopping empty games between %02d:00 and %02d:00 %s (checked every %dm)",
			cfg.NightShutdown.StartHour, cfg.NightShutdown.EndHour, cfg.Server.TZ, cfg.NightShutdown.CheckIntervalMinutes)
	} else {
		log.Printf("nightshutdown: disabled via config")
	}

	srv := &http.Server{
		Addr:    cfg.Server.Addr,
		Handler: auth.SecurityHeaders(cfg.Server.SecureCookies, newMux(app)),
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

// healthcheck is invoked as `crowsnest healthcheck` from the Dockerfile's
// HEALTHCHECK instruction — an in-process HTTP GET, avoiding a curl
// dependency in the runtime image. Returns a process exit code (0 = healthy).
func healthcheck() int {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:5000/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthz returned %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
