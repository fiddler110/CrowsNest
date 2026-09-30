// Package valheim implements Valheim's player tracking by tailing the
// dedicated server's own log output — it has no first-party status/query
// API. Join/leave detection is based on two log lines documented by the
// community around the lloesche/valheim-server-docker image (see
// docs/implementation-plan.md phase 10):
//
//	"Got handshake from client <steamid>"  — a client begins connecting
//	"Closing socket <steamid>"             — a client's connection closes
//
// The join/leave markers have NOT been verified with a real player connecting
// (the plan's "⚠️ spike" for this game); the regexes are deliberately
// permissive (matching everything after the marker phrase, not just digits)
// since newer Valheim versions are reported to prefix the id with "V_". Treat
// the count as best-effort. The readiness marker and startup milestones, by
// contrast, were read from a real lloesche/valheim-server container
// (2026-09-30, Valheim l-1.0.16): the same log tail also tells us when the
// world has finished loading, which docker-ps alone cannot.
package valheim

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

var (
	connectRe    = regexp.MustCompile(`Got handshake from client (\S+)`)
	disconnectRe = regexp.MustCompile(`Closing socket (\S+)`)

	// readyRe marks the world loaded and the server open for joins:
	//   "Loading: Done. Total seconds sinze ZNet start: ..."  (sic)
	//   "Opened Steam server"
	readyRe = regexp.MustCompile(`Loading: Done\.|Opened Steam server`)
)

// Startup drives Valheim's progress bar from the container's log. First boot
// spends its time in SteamCMD (same "Update state (0x61) downloading" lines
// as Palworld), mapped onto 10-70% by Parse; later milestones cover world
// load.
var Startup = &games.StartupMatcher{
	Milestones: []games.Milestone{
		{Pattern: regexp.MustCompile(`Downloading/updating/validating Valheim server`), Pct: 5, Label: "Checking for updates"},
		{Pattern: regexp.MustCompile(`Zonesystem Awake`), Pct: 72, Label: "Starting server"},
		{Pattern: regexp.MustCompile(`Load world:`), Pct: 80, Label: "Loading world"},
		{Pattern: regexp.MustCompile(`Loading: Generating locations`), Pct: 88, Label: "Generating world"},
		{Pattern: readyRe, Pct: 100, Label: "Server ready"},
	},
	Parse: parseDownload,
}

var downloadRe = regexp.MustCompile(`Update state \(0x61\) downloading, progress: (\d+(?:\.\d+)?)`)

func parseDownload(line string) (int, string, bool) {
	m := downloadRe.FindStringSubmatch(line)
	if m == nil {
		return 0, "", false
	}
	pct, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, "", false
	}
	return 10 + int(pct*0.6), fmt.Sprintf("Downloading server files (%.0f%%)", pct), true
}

// reattachDelay is how long Run waits before retrying after the container
// is stopped or the log stream ends unexpectedly.
const reattachDelay = 5 * time.Second

// Tracker maintains a live count of connected players by tailing
// `docker logs -f` for one Valheim container. It implements
// games.PlayerCounter. Build one with NewTracker and launch Run once as its
// own goroutine; PlayerCount is safe to call concurrently.
type Tracker struct {
	docker        *dockerctl.Client
	containerName string

	mu        sync.Mutex
	connected map[string]struct{}
	attached  bool
	ready     bool // saw readyRe in the current run's log
}

// Check implements games.StatusChecker: offline when the container isn't
// running; starting until the log tail has seen the world finish loading;
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

// NewTracker builds a Tracker for the named container. Its PlayerCount
// reports ok=false until Run has attached to a live log stream.
func NewTracker(docker *dockerctl.Client, containerName string) *Tracker {
	return &Tracker{
		docker:        docker,
		containerName: containerName,
		connected:     make(map[string]struct{}),
	}
}

// PlayerCount implements games.PlayerCounter. ok=false whenever no log
// stream is currently attached (container not running, or not yet
// (re)connected) — never assumed to mean zero players.
func (t *Tracker) PlayerCount(ctx context.Context) (count int, names []string, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.attached {
		return 0, nil, false
	}
	names = make([]string, 0, len(t.connected))
	for id := range t.connected {
		names = append(names, id)
	}
	return len(names), names, true
}

// Run attaches to the container's log stream and keeps re-attaching
// (resetting all tracked state on every reattach, since a fresh attach
// can't know who was connected before it started watching) until ctx is
// cancelled. Intended to be launched once as its own goroutine.
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
	t.connected = make(map[string]struct{})
	t.attached = false
	t.ready = false
	t.mu.Unlock()
}

// tailOnce streams the container's full log history plus live output,
// replaying every join/leave marker to reconstruct who's currently
// connected, until the stream ends (container stopped, or an error).
func (t *Tracker) tailOnce(ctx context.Context) {
	// Only this run's output: a restarted container keeps its earlier runs'
	// logs, whose "ready" line and joins must not leak into this one.
	since := ""
	if started, err := t.docker.StartedAt(ctx, t.containerName); err == nil {
		since = started.UTC().Format(time.RFC3339Nano)
	}
	rc, err := t.docker.Logs(ctx, t.containerName, since, "")
	if err != nil {
		log.Printf("valheim: attach to %s logs: %v", t.containerName, err)
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

// scan reads lines from r and updates connected-player state. Split out
// from tailOnce so tests can drive it directly without a real docker
// process.
func (t *Tracker) scan(r io.Reader) {
	scanner := bufio.NewScanner(r)
	// Player-count precision is best-effort here; skipping an
	// unexpectedly long line only means one join/leave event is missed,
	// not that the whole stream aborts.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		t.handleLine(scanner.Text())
	}
}

func (t *Tracker) handleLine(line string) {
	if readyRe.MatchString(line) {
		t.mu.Lock()
		t.ready = true
		t.mu.Unlock()
		return
	}
	if m := connectRe.FindStringSubmatch(line); m != nil {
		t.mu.Lock()
		t.connected[m[1]] = struct{}{}
		t.mu.Unlock()
		return
	}
	if m := disconnectRe.FindStringSubmatch(line); m != nil {
		t.mu.Lock()
		delete(t.connected, m[1])
		t.mu.Unlock()
	}
}
