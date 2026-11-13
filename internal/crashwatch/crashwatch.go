// Package crashwatch notices game containers that die on their own and raises
// an alert when one keeps doing it. It reads each container's last exit from
// docker, so it needs no cooperation from the stop path.
//
// What counts as a crash: a run that ended with an exit code other than 0 (a
// clean exit) and 143 (SIGTERM, what a stop sends), and other than 137 unless
// docker says the kernel killed it for memory (137 is also what `docker stop`
// produces when a game outlasts its grace period, which is a stop, not a
// crash). A segfault (139), an abort (134) or an error exit all count.
package crashwatch

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/history"
	"github.com/fiddler110/crowsnest/internal/notify"
)

// Defaults for a Watcher's thresholds.
const (
	DefaultCrashes  = 3
	DefaultWindow   = 15 * time.Minute
	DefaultInterval = 30 * time.Second
)

// StateReader reads a container's state; satisfied by *dockerctl.Client.
type StateReader interface {
	State(ctx context.Context, name string) (dockerctl.ContainerState, error)
}

// Notifier delivers an alert; satisfied by *notify.Discord.
type Notifier interface {
	Notify(ctx context.Context, message string)
}

// Crashed reports whether a finished run with this exit code and OOM flag
// was a crash rather than a stop.
func Crashed(exitCode int, oomKilled bool) bool {
	switch exitCode {
	case 0, 143:
		return false
	case 137:
		return oomKilled
	}
	return true
}

type gameState struct {
	seen      bool
	finished  time.Time
	restarts  int
	crashes   []time.Time // inside the window
	total     uint64
	alerted   bool
	lastCrash time.Time
}

// Watcher polls every registered game. Build one with New.
type Watcher struct {
	registry *games.Registry
	docker   StateReader

	// Crashes inside Window make a loop. Zero values use the defaults.
	Crashes  int
	Window   time.Duration
	Interval time.Duration

	Notifier Notifier
	History  history.Recorder
	Now      func() time.Time

	mu    sync.Mutex
	state map[string]*gameState
}

// New builds a Watcher with the default thresholds.
func New(registry *games.Registry, docker StateReader) *Watcher {
	return &Watcher{registry: registry, docker: docker, state: map[string]*gameState{}}
}

func (w *Watcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Watcher) threshold() int {
	if w.Crashes > 0 {
		return w.Crashes
	}
	return DefaultCrashes
}

func (w *Watcher) window() time.Duration {
	if w.Window > 0 {
		return w.Window
	}
	return DefaultWindow
}

// Run polls until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	iv := w.Interval
	if iv <= 0 {
		iv = DefaultInterval
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		w.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick checks every game once.
func (w *Watcher) Tick(ctx context.Context) {
	live := map[string]bool{}
	for _, d := range w.registry.All() {
		live[d.ID] = true
		w.check(ctx, d)
	}
	w.mu.Lock()
	for id := range w.state {
		if !live[id] {
			delete(w.state, id)
		}
	}
	w.mu.Unlock()
}

func (w *Watcher) check(ctx context.Context, d games.GameDef) {
	st, err := w.docker.State(ctx, d.ContainerName)
	if err != nil {
		return // not created yet, or docker is down: nothing to learn
	}
	now := w.now()
	w.mu.Lock()
	g := w.state[d.ID]
	if g == nil {
		g = &gameState{}
		w.state[d.ID] = g
	}
	first := !g.seen
	newRun := st.FinishedAt.After(g.finished)
	// Runs that ended since the last look: one if FinishedAt moved, and more
	// when docker's restart policy cycled the container between two polls (we
	// only see the last exit code, so earlier runs share its verdict).
	ended := max(st.RestartCount-g.restarts, 0)
	if newRun {
		ended = max(ended, 1)
	}
	g.seen, g.restarts = true, st.RestartCount
	if newRun {
		g.finished = st.FinishedAt
	}
	// The first sighting only records where things stand: a crash from before
	// CrowsNest started is history, not news.
	crashed := 0
	if !first && Crashed(st.ExitCode, st.OOMKilled) {
		crashed = ended
	}
	for i := 0; i < crashed; i++ {
		g.crashes = append(g.crashes, now)
		g.total++
		g.lastCrash = now
	}
	cut := now.Add(-w.window())
	kept := g.crashes[:0]
	for _, t := range g.crashes {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	g.crashes = kept
	looping := len(g.crashes) >= w.threshold()
	raise := looping && !g.alerted
	if looping {
		g.alerted = true
	} else {
		g.alerted = false
	}
	n := len(g.crashes)
	w.mu.Unlock()

	if crashed > 0 {
		detail := fmt.Sprintf("exit code %d", st.ExitCode)
		if st.OOMKilled {
			detail += " (out of memory)"
		}
		if crashed > 1 {
			detail += fmt.Sprintf(", %d crashes since the last check", crashed)
		}
		log.Printf("crashwatch: %s crashed: %s", d.ID, detail)
		if w.History != nil {
			w.History.Record(history.KindCrash, d.ID, "", detail)
		}
	}
	if raise {
		log.Printf("crashwatch: %s is crash-looping (%d crashes in %s)", d.ID, n, w.window())
		if w.History != nil {
			w.History.Record(history.KindCrashLoop, d.ID, "", fmt.Sprintf("%d crashes in %s", n, w.window()))
		}
		if w.Notifier != nil {
			nctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			w.Notifier.Notify(notify.WithGame(nctx, d.ID), fmt.Sprintf(
				"⚠️ **%s** is crash-looping: %d crashes in %s. It will keep restarting until someone stops it or fixes it.",
				d.DisplayName, n, w.window()))
		}
	}
}

// Total is how many crashes of id have been seen since CrowsNest started.
func (w *Watcher) Total(id string) uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if g := w.state[id]; g != nil {
		return g.total
	}
	return 0
}

// Looping reports whether id is currently over the crash-loop threshold.
func (w *Watcher) Looping(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if g := w.state[id]; g != nil {
		return g.alerted
	}
	return false
}
