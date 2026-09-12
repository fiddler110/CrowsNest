// Package valheim implements Valheim's player tracking by tailing the
// dedicated server's own log output — it has no first-party status/query
// API. Join/leave detection is based on two log lines documented by the
// community around the lloesche/valheim-server-docker image (see
// docs/implementation-plan.md phase 10):
//
//	"Got handshake from client <steamid>"  — a client begins connecting
//	"Closing socket <steamid>"             — a client's connection closes
//
// This has NOT been verified against a real running Valheim server (the
// plan's "⚠️ spike" for this game); the regexes are deliberately permissive
// (matching everything after the marker phrase, not just digits) since
// newer Valheim versions are reported to prefix the id with "V_". Treat
// this as a best-effort count, not a verified-accurate one.
package valheim

import (
	"bufio"
	"context"
	"io"
	"log"
	"regexp"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
)

var (
	connectRe    = regexp.MustCompile(`Got handshake from client (\S+)`)
	disconnectRe = regexp.MustCompile(`Closing socket (\S+)`)
)

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
	t.mu.Unlock()
}

// tailOnce streams the container's full log history plus live output,
// replaying every join/leave marker to reconstruct who's currently
// connected, until the stream ends (container stopped, or an error).
func (t *Tracker) tailOnce(ctx context.Context) {
	rc, err := t.docker.Logs(ctx, t.containerName, "", "")
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
