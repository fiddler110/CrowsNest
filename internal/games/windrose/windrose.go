// Package windrose provides Windrose's container-status detection. The
// server prints a ready marker to its stdout, so a log-following Tracker
// (modelled on the Valheim one) distinguishes "starting" from "online"
// without any `docker exec`.
package windrose

import (
	"bufio"
	"context"
	"io"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

// ReadyMarker is the log line (on the container's stdout) that marks the
// server as ready for players.
const ReadyMarker = "Host server is ready for owner to connect"

// reattachDelay is how long Run waits before retrying after the container
// is stopped or the log stream ends unexpectedly.
const reattachDelay = 5 * time.Second

// Tracker follows `docker logs -f` for one Windrose container and reports
// starting vs. online. It implements games.StatusChecker. Launch Run once as
// its own goroutine; Check is safe to call concurrently.
type Tracker struct {
	docker        *dockerctl.Client
	containerName string

	mu    sync.Mutex
	ready bool // saw ReadyMarker in the current run's log
}

// NewTracker builds a Tracker for the named container.
func NewTracker(docker *dockerctl.Client, containerName string) *Tracker {
	return &Tracker{docker: docker, containerName: containerName}
}

// Check implements games.StatusChecker: offline when the container isn't
// running; starting until the ready marker has been seen in the current
// run; online after that.
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

// Run attaches to the container's log stream and keeps re-attaching
// (resetting state each time) until ctx is cancelled.
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
	t.ready = false
	t.mu.Unlock()
}

// tailOnce streams this run's log output until the stream ends.
func (t *Tracker) tailOnce(ctx context.Context) {
	// Only this run's output: a restarted container keeps its earlier runs'
	// logs, whose ready line must not leak into this one.
	since := ""
	if started, err := t.docker.StartedAt(ctx, t.containerName); err == nil {
		since = started.UTC().Format(time.RFC3339Nano)
	}
	rc, err := t.docker.Logs(ctx, t.containerName, since, "")
	if err != nil {
		log.Printf("windrose: attach to %s logs: %v", t.containerName, err)
		select {
		case <-ctx.Done():
		case <-time.After(reattachDelay):
		}
		return
	}
	defer rc.Close()
	t.scan(rc)
}

// scan reads lines from r and latches ready. Split out for tests.
func (t *Tracker) scan(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), ReadyMarker) {
			t.mu.Lock()
			t.ready = true
			t.mu.Unlock()
		}
	}
}

// Startup is Windrose's startup-progress matcher: a single milestone.
var Startup = &games.StartupMatcher{
	Milestones: []games.Milestone{
		{Pattern: regexp.MustCompile(regexp.QuoteMeta(ReadyMarker)), Pct: 100, Label: "Host server ready"},
	},
}
