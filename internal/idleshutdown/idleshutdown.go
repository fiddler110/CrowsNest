// Package idleshutdown auto-stops a game once it has run with zero players
// connected for a configurable grace period. It never assumes a game is
// empty from a player count it couldn't determine (auth failure,
// unreachable API, container not running) — only a positive, sustained
// zero-player reading ever triggers a stop. Simpler than the original
// Python CrowsNest's overnight cron window (see internal/nightshutdown for
// that, ported separately in Phase 11): this runs continuously and reacts
// purely to occupancy, not time of day.
package idleshutdown

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
)

// Stopper stops a registered game by ID — the subset of
// *exclusivity.Manager the idle-shutdown loop needs, kept as an interface
// so tests don't need a real docker client.
type Stopper interface {
	Stop(ctx context.Context, id string) error
}

// Notifier reports a message about a CrowsNest-initiated event. Satisfied
// by *notify.Discord; optional — a nil Notifier on Manager just skips
// notifying.
type Notifier interface {
	Notify(ctx context.Context, message string)
}

// Manager runs the idle-shutdown check on a timer. Build one with New; the
// zero value is not usable.
type Manager struct {
	registry *games.Registry
	stopper  Stopper

	idleDuration  time.Duration
	checkInterval time.Duration

	// Notifier, when set, is told about every stop this manager triggers.
	// Optional — leave nil to disable notifications.
	Notifier Notifier

	// Now overrides time.Now. Intended for tests; production callers should
	// leave it unset.
	Now func() time.Time

	// lastNonZero tracks, per game ID, the last time it was observed online
	// with a nonzero (or undeterminable-turned-determinable) player count.
	// A game absent from this map is either not online or was only just
	// observed coming online this tick.
	lastNonZero map[string]time.Time
}

// New builds a Manager that checks every game in registry once per
// checkInterval, stopping (via stopper) any game that's been online with
// zero players for idleDuration straight.
func New(registry *games.Registry, stopper Stopper, idleDuration, checkInterval time.Duration) *Manager {
	return &Manager{
		registry:      registry,
		stopper:       stopper,
		idleDuration:  idleDuration,
		checkInterval: checkInterval,
		lastNonZero:   make(map[string]time.Time),
	}
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Run ticks every checkInterval, checking every registered game, until ctx
// is cancelled. Intended to be launched once as its own goroutine.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Tick(ctx)
		}
	}
}

// Tick checks every registered game once. Exported so Run's ticker and
// tests can both drive it directly.
func (m *Manager) Tick(ctx context.Context) {
	for _, d := range m.registry.All() {
		m.checkGame(ctx, d)
	}
}

func (m *Manager) checkGame(ctx context.Context, d games.GameDef) {
	if d.Status == nil {
		return
	}
	status, err := d.Status.Check(ctx, d.ContainerName)
	if err != nil || status != games.StatusOnline {
		// Not confirmedly online: drop any tracked grace period so the next
		// time this game comes online it starts a fresh one, rather than
		// getting credit (or blame) for time spent stopped or starting.
		delete(m.lastNonZero, d.ID)
		return
	}

	now := m.now()
	last, tracked := m.lastNonZero[d.ID]
	if !tracked {
		// Just (as far as we've observed) came online: seed the grace
		// period from now, so a freshly started empty server isn't
		// instantly judged idle against a start time we never saw.
		m.lastNonZero[d.ID] = now
		return
	}

	if d.Players == nil {
		return // no PlayerCounter wired for this game -> never auto-stop it
	}
	count, _, ok := d.Players.PlayerCount(ctx)
	if !ok {
		return // undeterminable -> never assume zero
	}
	if count > 0 {
		m.lastNonZero[d.ID] = now
		return
	}
	if now.Sub(last) < m.idleDuration {
		return
	}

	log.Printf("idleshutdown: stopping %s after %s with no players", d.ID, m.idleDuration)
	if err := m.stopper.Stop(ctx, d.ID); err != nil {
		log.Printf("idleshutdown: stop %s: %v", d.ID, err)
		return
	}
	delete(m.lastNonZero, d.ID)
	if m.Notifier != nil {
		m.Notifier.Notify(ctx, fmt.Sprintf(
			"\U0001f634 **%s** stopped automatically after %s with no players.",
			d.DisplayName, m.idleDuration,
		))
	}
}
