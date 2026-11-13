// Package logtrack is the shared log-follow engine behind every game that is
// observed through its container's own output (docs/modularization-plan.md,
// "log_markers"). It follows `docker logs -f`, latches a ready marker,
// optionally tracks who is connected from join/leave patterns, and resets all
// of it whenever the container restarts. Valheim and Windrose use it today;
// a module.yaml `log_markers` probe will build the same Spec from data.
package logtrack

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

// reattachDelay is how long Run waits before retrying after the container
// is stopped or the log stream ends unexpectedly.
const reattachDelay = 5 * time.Second

// Spec says what to look for in the log. Only Ready is required.
type Spec struct {
	// Name prefixes log messages ("valheim").
	Name string
	// Ready marks the server open for players.
	Ready *regexp.Regexp
	// Join and Leave capture a player id in group 1. Both nil disables
	// player tracking.
	Join, Leave *regexp.Regexp
	// World captures a world name in group 1 (optional, display only).
	World *regexp.Regexp
	// Player (optional) captures a player's display name in group 1. It is
	// given to the most recent joiner that has none yet, so a game that logs
	// a bare id first and the name a line later shows names, not ids.
	Player *regexp.Regexp
	// Codes are labelled values to show on the card, each captured from the
	// log in group 1 (a join code); they reset when the container restarts.
	Codes []Code
}

// Code is one value to lift out of the log.
type Code struct {
	Label string
	Re    *regexp.Regexp
}

// Tracker implements games.StatusChecker, and (when Join/Leave are set)
// games.PlayerCounter and games.InfoProvider. Launch Run once as its own
// goroutine; everything else is safe to call concurrently.
type Tracker struct {
	docker        *dockerctl.Client
	containerName string
	spec          Spec

	mu        sync.Mutex
	connected map[string]struct{}
	attached  bool
	ready     bool
	world     string
	names     map[string]string // player id -> display name
	pending   string            // latest joiner still without a name
	codes     map[string]string // label -> value
}

// New builds a Tracker for the named container.
func New(docker *dockerctl.Client, containerName string, spec Spec) *Tracker {
	return &Tracker{docker: docker, containerName: containerName, spec: spec, connected: map[string]struct{}{}, names: map[string]string{}, codes: map[string]string{}}
}

// Check implements games.StatusChecker: offline when the container isn't
// running; starting until the ready marker has been seen in the current run;
// online after that.
func (t *Tracker) Check(ctx context.Context, containerName string) (games.Status, error) {
	running, err := t.docker.Running(ctx, containerName)
	if err != nil {
		return games.StatusUnknown, err
	}
	if !running {
		return games.StatusOffline, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ready {
		return games.StatusOnline, nil
	}
	return games.StatusStarting, nil
}

// PlayerCount implements games.PlayerCounter. ok=false whenever no log stream
// is attached (container not running, or not yet (re)connected): never
// assumed to mean zero players.
func (t *Tracker) PlayerCount(ctx context.Context) (count int, names []string, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.attached {
		return 0, nil, false
	}
	names = make([]string, 0, len(t.connected))
	for id := range t.connected {
		if n := t.names[id]; n != "" {
			id = n
		}
		names = append(names, id)
	}
	sort.Strings(names)
	return len(names), names, true
}

// Info implements games.InfoProvider from what the log tail knows.
// available=false until the tail is attached to a running container.
func (t *Tracker) Info(ctx context.Context) (map[string]any, bool) {
	out := map[string]any{"available": false}
	t.mu.Lock()
	attached, ready, world, players := t.attached, t.ready, t.world, len(t.connected)
	t.mu.Unlock()
	if !attached {
		return out, true
	}
	out["available"] = true
	if ready {
		out["state"] = "online"
	} else {
		out["state"] = "starting"
	}
	if started, err := t.docker.StartedAt(ctx, t.containerName); err == nil {
		out["uptime"] = uptimeString(time.Since(started))
	}
	if world != "" {
		out["world"] = world
	}
	out["players_connected"] = players
	return out, true
}

func uptimeString(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days, hours, mins := int(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

// Run attaches to the container's log stream and keeps re-attaching,
// resetting all tracked state on every reattach (a fresh attach can't know
// who was connected before it started watching), until ctx is cancelled.
func (t *Tracker) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		running, err := t.docker.Running(ctx, t.containerName)
		if err != nil || !running {
			t.reset()
			select {
			case <-ctx.Done():
				return
			case <-time.After(reattachDelay):
			}
			continue
		}
		t.tailOnce(ctx)
		t.reset()
	}
}

func (t *Tracker) reset() {
	t.mu.Lock()
	t.connected = map[string]struct{}{}
	t.attached = false
	t.ready = false
	t.world = ""
	t.names = map[string]string{}
	t.pending = ""
	t.codes = map[string]string{}
	t.mu.Unlock()
}

// tailOnce streams this run's log output (replaying history to reconstruct
// state) until the stream ends.
func (t *Tracker) tailOnce(ctx context.Context) {
	// Only this run's output: a restarted container keeps its earlier runs'
	// logs, whose ready line and joins must not leak into this one.
	since := ""
	if started, err := t.docker.StartedAt(ctx, t.containerName); err == nil {
		since = started.UTC().Format(time.RFC3339Nano)
	}
	rc, err := t.docker.Logs(ctx, t.containerName, since, "")
	if err != nil {
		log.Printf("%s: attach to %s logs: %v", t.spec.Name, t.containerName, err)
		select {
		case <-ctx.Done():
		case <-time.After(reattachDelay):
		}
		return
	}
	defer rc.Close()

	t.mu.Lock()
	t.attached = true
	t.mu.Unlock()

	t.scan(rc)
}

// Ready reports whether the ready marker has been seen in the current run.
func (t *Tracker) Ready() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ready
}

// Replay feeds a recorded log through the tracker as if it were attached to a
// live stream. For tests and fixtures.
func (t *Tracker) Replay(r io.Reader) {
	t.mu.Lock()
	t.attached = true
	t.mu.Unlock()
	t.scan(r)
}

// scan reads lines from r and updates state. Split out so tests can drive it
// without a docker process.
func (t *Tracker) scan(r io.Reader) {
	scanner := bufio.NewScanner(r)
	// Skipping an unexpectedly long line only loses one event.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		t.handleLine(scanner.Text())
	}
}

func (t *Tracker) handleLine(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.spec.World != nil {
		if m := t.spec.World.FindStringSubmatch(line); m != nil {
			t.world = m[1]
		}
	}
	for _, c := range t.spec.Codes {
		if m := c.Re.FindStringSubmatch(line); m != nil {
			t.codes[c.Label] = m[1]
		}
	}
	if t.spec.Player != nil && t.pending != "" {
		if m := t.spec.Player.FindStringSubmatch(line); m != nil {
			if _, here := t.connected[t.pending]; here {
				t.names[t.pending] = m[1]
			}
			t.pending = ""
		}
	}
	if t.spec.Ready.MatchString(line) {
		t.ready = true
		return
	}
	if t.spec.Join != nil {
		if m := t.spec.Join.FindStringSubmatch(line); m != nil {
			t.connected[m[1]] = struct{}{}
			t.pending = m[1]
			return
		}
	}
	if t.spec.Leave != nil {
		if m := t.spec.Leave.FindStringSubmatch(line); m != nil {
			delete(t.connected, m[1])
			delete(t.names, m[1])
			if t.pending == m[1] {
				t.pending = ""
			}
		}
	}
}

// ConnectValues implements games.ConnectLister: the codes found in this run's
// log, in the order the module declared them.
func (t *Tracker) ConnectValues() []games.ConnectSecret {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []games.ConnectSecret
	for _, c := range t.spec.Codes {
		if v := t.codes[c.Label]; v != "" {
			out = append(out, games.ConnectSecret{Label: c.Label, Value: v})
		}
	}
	return out
}
