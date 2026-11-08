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

	"github.com/fiddler110/crowsnest/internal/dockerguard"
)

// runGuard serves the scoped Docker API guard: crowsnest's docker_host points
// (through execguard, if exec is used) at this, and this talks to the Docker
// socket. It refuses to start without a valid GUARD_SCOPES.
func runGuard(args []string) error {
	fs := flag.NewFlagSet("guard", flag.ExitOnError)
	listen := fs.String("listen", ":2375", "address to listen on")
	socket := fs.String("socket", envOr("GUARD_SOCKET", "/var/run/docker.sock"), "Docker socket (or $GUARD_SOCKET)")
	_ = fs.Parse(args)

	scopes, err := dockerguard.LoadScopes(os.Getenv("GUARD_SCOPES"))
	if err != nil {
		return fmt.Errorf("crowsnest guard: refusing to start, bad scope configuration: %w", err)
	}
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
	for _, s := range scopes {
		fmt.Printf("crowsnest guard scope %s: images=%v binds=%v volumes=%v networks=%v ipv4=%v ports=%v exec=%v secopts=%v cap_add=%v\n",
			s.Name, sortedKeys(s.Images), s.Binds, s.Volumes, sortedKeys(s.Networks), s.IPv4, s.Ports, s.Exec, sortedKeys(s.SecOpts), sortedKeys(s.CapAdd)) // #nosec G705 G706 -- operator configuration, not request data
	}

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	fmt.Printf("crowsnest guard on %s, %d scope(s), socket %s\n", l.Addr(), len(scopes), *socket) // #nosec G705 G706 -- operator-supplied command-line flags
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return g.ServeContext(ctx, l)
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
