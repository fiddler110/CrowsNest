package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerguard"
	"github.com/fiddler110/crowsnest/internal/modules"
)

// runGuard serves the scoped Docker API guard: crowsnest's docker_host points
// (through execguard, if exec is used) at this, and this talks to the Docker
// socket. It refuses to start without a valid GUARD_SCOPES.
func runGuard(args []string) error {
	fs := flag.NewFlagSet("guard", flag.ExitOnError)
	listen := fs.String("listen", ":2375", "address to listen on")
	socket := fs.String("socket", envOr("GUARD_SOCKET", "/var/run/docker.sock"), "Docker socket (or $GUARD_SOCKET)")
	withExec := fs.Bool("exec", os.Getenv("GUARD_EXEC") == "1", "also run the exec allowlist (execguard) in front of the guard, in this process (or GUARD_EXEC=1)")
	_ = fs.Parse(args)

	src := dockerguard.Sources{Base: os.Getenv("GUARD_SCOPES"), ManagedFile: os.Getenv("GUARD_SCOPES_FILE"), PolicyFile: os.Getenv("GUARD_POLICY"), Defaults: policyDefaults()}
	src.AllowedFile = dockerguard.AllowedPath(src.ManagedFile)
	res, err := src.Load()
	if err != nil {
		return fmt.Errorf("crowsnest guard: refusing to start, bad scope configuration: %w", err)
	}
	scopes := res.Scopes
	g := dockerguard.New(*socket, scopes)
	g.Logf = func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
	if v := os.Getenv("GUARD_MAX_RESPONSE"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return fmt.Errorf("crowsnest guard: refusing to start, GUARD_MAX_RESPONSE must be a positive number of bytes, not %q", v)
		}
		g.MaxResponse = n
	}
	if v := os.Getenv("GUARD_MAX_CONNECTIONS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return fmt.Errorf("crowsnest guard: refusing to start, GUARD_MAX_CONNECTIONS must be a positive number, not %q", v)
		}
		g.MaxConns = n
	}
	for _, e := range res.Rejected {
		fmt.Fprintf(os.Stderr, "crowsnest guard: not loading %v\n", e) // #nosec G705 G706 -- operator configuration
	}
	for _, s := range scopes {
		fmt.Printf("crowsnest guard scope %s: images=%v binds=%v volumes=%v networks=%v ipv4=%v ports=%v exec=%v secopts=%v cap_add=%v\n",
			s.Name, sortedKeys(s.Images), s.Binds, s.Volumes, sortedKeys(s.Networks), s.IPv4, s.Ports, s.Exec, sortedKeys(s.SecOpts), sortedKeys(s.CapAdd)) // #nosec G705 G706 -- operator configuration, not request data
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// With --exec the guard listens on loopback only, where nothing outside this container can reach it, and
	// the exec allowlist takes the public address and forwards to it: the same two layers as running execguard
	// as its own container, without the second container.
	guardAddr := *listen
	if *withExec {
		guardAddr = "127.0.0.1:0"
	}
	l, err := net.Listen("tcp", guardAddr)
	if err != nil {
		return err
	}
	fmt.Printf("crowsnest guard on %s, %d scope(s), socket %s\n", l.Addr(), len(scopes), *socket) // #nosec G705 G706 -- operator-supplied command-line flags
	if src.ManagedFile != "" {
		kick := make(chan struct{}, 1)
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for range hup {
				select {
				case kick <- struct{}{}:
				default:
				}
			}
		}()
		go g.Watch(ctx, src, 2*time.Second, kick, res)
		fmt.Printf("crowsnest guard watching %s inside policy %s (SIGHUP reloads at once)\n", src.ManagedFile, src.PolicyFile) // #nosec G705 G706 -- operator-supplied environment
	}
	if !*withExec {
		return g.ServeContext(ctx, l)
	}
	execSrv, err := newExecProxy(ctx, *listen, "tcp://"+l.Addr().String())
	if err != nil {
		return err
	}
	errc := make(chan error, 2)
	go func() { errc <- g.ServeContext(ctx, l) }()
	go func() { errc <- serveUntilDone(ctx, execSrv) }()
	err = <-errc
	stop() // one side ending takes the other down with it
	<-errc
	return err
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// policyDefaults is what a policy that leaves out images or networks gets: the
// images of the bundled modules and the games network from config.yaml. The
// config is optional for the guard (it is only mounted for the exec allowlist),
// so without one the network is the default, crowsnest-games-net.
func policyDefaults() dockerguard.Defaults {
	var p modules.Platform
	if cfg, err := config.Load(configPath()); err == nil {
		p = modules.PlatformFrom(cfg.Platform)
	}
	return modules.PolicyDefaults(p)
}
