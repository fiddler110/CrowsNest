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
	"github.com/fiddler110/crowsnest/internal/managed"
	"github.com/fiddler110/crowsnest/internal/modules"
)

// execRules lists every command CrowsNest itself ever runs with `docker
// exec`: each game's configured backup (and its file listing). Nothing
// else is allowed through the guard.
func execRules(cfg *config.Config) []execguard.Rule {
	var rules []execguard.Rule
	for _, g := range cfg.Games {
		if g.Backup == nil {
			continue
		}
		rules = append(rules, execguard.Rule{Container: g.ContainerName, Cmd: g.Backup.Exec})
		if dir := g.Backup.ExecListDir(); dir != "" {
			rules = append(rules, execguard.Rule{Container: g.ContainerName, Cmd: backup.ListArgs(dir)})
		}
		if g.Backup.Keep > 0 {
			rules = append(rules, execguard.Rule{Container: g.ContainerName, Cmd: backup.PruneArgs(g.Backup.ExecListDir(), g.Backup.Keep)})
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv, err := newExecProxy(ctx, *listen, *upstream)
	if err != nil {
		return err
	}
	return serveUntilDone(ctx, srv)
}

// newExecProxy builds the exec allowlist proxy from config.yaml (and, for
// dashboard-enabled games, their modules' backup commands, reloaded live while
// ctx lives). It forwards everything that is not an exec route to upstream.
func newExecProxy(ctx context.Context, listen, upstream string) (*http.Server, error) {
	cfg, err := config.Load(configPath())
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	rules := execRules(cfg)
	var mods *modules.Set
	if cfg.Managed.Dir != "" {
		// Dashboard-enabled games: their module's backup command, reloaded as games come and go.
		if mods, err = modules.ForConfig(cfg, log.Printf); err != nil {
			return nil, fmt.Errorf("load modules: %w", err)
		}
		more, err := managed.ExecRulesFor(cfg.Managed.Dir, cfg.Managed.PolicyFile, mods, cfg.Platform.BackupsRoot != "")
		if err != nil {
			return nil, err
		}
		rules = append(rules, more...)
	}
	g, err := execguard.New(upstream, rules)
	if err != nil {
		return nil, err
	}
	g.Logf = log.Printf
	log.Printf("execguard: %d allowlisted command(s), listening on %q, upstream %q", len(rules), listen, upstream) // #nosec G706 -- operator-supplied command-line flags, not request data
	if mods != nil {
		go watchManagedRules(ctx, g, execRules(cfg), cfg.Managed.Dir, cfg.Managed.PolicyFile, mods, cfg.Platform.BackupsRoot != "")
	}
	return &http.Server{Addr: listen, Handler: g, ReadHeaderTimeout: 10 * time.Second}, nil
}

// serveUntilDone runs srv until ctx ends, then shuts it down.
func serveUntilDone(ctx context.Context, srv *http.Server) error {
	go func() { // #nosec G118 -- ctx has ended by now; the shutdown needs a fresh deadline of its own
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

// watchManagedRules re-reads the managed games every few seconds and swaps the
// allowlist when it changes. A read that fails keeps the rules in force.
func watchManagedRules(ctx context.Context, g *execguard.Guard, static []execguard.Rule, dir, policyFile string, mods *modules.Set, sharedBackups bool) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	last := len(static)
	var lastKey string
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		more, err := managed.ExecRulesFor(dir, policyFile, mods, sharedBackups)
		if err != nil {
			log.Printf("execguard: keeping the current allowlist: %v", err)
			continue
		}
		key := fmt.Sprint(more)
		if key == lastKey {
			continue
		}
		lastKey = key
		g.SetRules(append(append([]execguard.Rule{}, static...), more...))
		log.Printf("execguard: %d allowlisted command(s) (%d from dashboard-enabled games)", last+len(more), len(more))
	}
}
