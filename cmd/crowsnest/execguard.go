package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fiddler110/crowsnest/internal/backup"
	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/execguard"
	"github.com/fiddler110/crowsnest/internal/games/windrose"
)

// execRules lists every command CrowsNest itself ever runs with `docker
// exec`: each game's configured backup (and its file listing) plus Windrose's
// readiness check. Nothing else is allowed through the guard.
func execRules(cfg *config.Config) []execguard.Rule {
	var rules []execguard.Rule
	for _, g := range cfg.Games {
		if g.ID == "windrose" {
			rules = append(rules, execguard.Rule{Container: g.ContainerName, Cmd: windrose.ReadyArgs()})
		}
		if g.Backup == nil {
			continue
		}
		rules = append(rules, execguard.Rule{Container: g.ContainerName, Cmd: g.Backup.Exec})
		if g.Backup.ListDir != "" {
			rules = append(rules, execguard.Rule{Container: g.ContainerName, Cmd: backup.ListArgs(g.Backup.ListDir)})
		}
	}
	return rules
}

// runExecGuard serves the exec-allowlisting proxy: crowsnest's docker_host
// points here, and this forwards to docker-socket-proxy (which has EXEC=1).
func runExecGuard(args []string) error {
	fs := flag.NewFlagSet("execguard", flag.ExitOnError)
	listen := fs.String("listen", ":2375", "address to listen on")
	upstream := fs.String("upstream", os.Getenv("EXECGUARD_UPSTREAM"), "docker-socket-proxy URL, e.g. tcp://dockerproxy:2375 (or $EXECGUARD_UPSTREAM)")
	_ = fs.Parse(args)
	if *upstream == "" {
		return fmt.Errorf("execguard: --upstream or EXECGUARD_UPSTREAM is required")
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	rules := execRules(cfg)
	g, err := execguard.New(*upstream, rules)
	if err != nil {
		return err
	}
	g.Logf = log.Printf
	log.Printf("execguard: %d allowlisted command(s), listening on %q, upstream %q", len(rules), *listen, *upstream) // #nosec G706 -- operator-supplied command-line flags, not request data

	srv := &http.Server{Addr: *listen, Handler: g, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
