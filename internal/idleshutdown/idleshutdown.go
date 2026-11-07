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
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/history"
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

	// History, when set, records each automatic stop.
	History history.Recorder

	// Settings, when set, is consulted on every tick instead of the fixed
	// idleDuration: it returns whether idle shutdown is currently enabled
	// and the grace period to apply. This is how runtime settings changes
	// take effect without a restart.
	Settings func() (enabled bool, idle time.Duration)

	// Now overrides time.Now. Intended for tests; production callers should
	// leave it unset.
	Now func() time.Time

	// lastNonZero tracks, per game ID, the last time it was observed online
	// with a nonzero (or undeterminable-turned-determinable) player count.
	// A game absent from this map is either not online or was only just
	// observed coming online this tick.
	lastNonZero map[string]time.Time

	// mu guards lastNonZero, empty and idleFor, which the Run goroutine
	// writes while HTTP handlers read them via IdleRemaining.
	mu sync.Mutex
	// empty marks games whose latest determinable reading was zero players.
	empty map[string]bool
	// idleFor is the grace period applied on the most recent tick.
	idleFor time.Duration
}

// IdleRemaining reports how long until id is auto-stopped, as of the most
// recent check. ok is false when no countdown is running: idle shutdown is
// off, the game isn't online, has players, or its count can't be read.
func (m *Manager) IdleRemaining(id string) (time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	last, tracked := m.lastNonZero[id]
	if !tracked || !m.empty[id] || m.idleFor <= 0 {
		return 0, false
	}
	return max(0, m.idleFor-m.now().Sub(last)), true
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
		empty:         make(map[string]bool),
		idleFor:       idleDuration,
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
	idle := m.idleDuration
	if m.Settings != nil {
		enabled, dur := m.Settings()
		if !enabled {
			// Forget every grace period so re-enabling starts fresh rather
			// than stopping a game on time accrued while it was switched off.
			m.mu.Lock()
			clear(m.lastNonZero)
			clear(m.empty)
			m.mu.Unlock()
			return
		}
		idle = dur
	}
	m.mu.Lock()
	m.idleFor = idle
	m.mu.Unlock()
	for _, d := range m.registry.All() {
		m.checkGame(ctx, d, idle)
	}
}

// forget drops all tracking for id.
func (m *Manager) forget(id string) {
	m.mu.Lock()
	delete(m.lastNonZero, id)
	delete(m.empty, id)
	m.mu.Unlock()
}

// observe records a reading for id. isEmpty is only meaningful with a
// determinable count; undeterminable readings clear the empty flag so no
// countdown is shown.
func (m *Manager) observe(id string, last time.Time, isEmpty bool) {
	m.mu.Lock()
	m.lastNonZero[id] = last
	m.empty[id] = isEmpty
	m.mu.Unlock()
}

func (m *Manager) checkGame(ctx context.Context, d games.GameDef, idleDuration time.Duration) {
	if d.Status == nil {
		return
	}
	status, err := d.Status.Check(ctx, d.ContainerName)
	if err != nil || status != games.StatusOnline {
		// Not confirmedly online: drop any tracked grace period so the next
		// time this game comes online it starts a fresh one, rather than
		// getting credit (or blame) for time spent stopped or starting.
		m.forget(d.ID)
		return
	}

	now := m.now()
	m.mu.Lock()
	last, tracked := m.lastNonZero[d.ID]
	m.mu.Unlock()
	if !tracked {
		// Just (as far as we've observed) came online: seed the grace
		// period from now, so a freshly started empty server isn't
		// instantly judged idle against a start time we never saw.
		m.observe(d.ID, now, false)
		return
	}

	if d.Players == nil {
		return // no PlayerCounter wired for this game -> never auto-stop it
	}
	count, _, ok := d.Players.PlayerCount(ctx)
	if !ok {
		m.observe(d.ID, last, false) // undeterminable -> never assume zero
		return
	}
	if count > 0 {
		m.observe(d.ID, now, false)
		return
	}
	m.observe(d.ID, last, true)
	if now.Sub(last) < idleDuration {
		return
	}

	log.Printf("idleshutdown: stopping %s after %s with no players", d.ID, idleDuration)
	if err := m.stopper.Stop(ctx, d.ID); err != nil {
		log.Printf("idleshutdown: stop %s: %v", d.ID, err)
		return
	}
	m.forget(d.ID)
	if m.History != nil {
		m.History.Record(history.KindAutoStop, d.ID, "", fmt.Sprintf("idle: no players for %s", idleDuration))
	}
	if m.Notifier != nil {
		m.Notifier.Notify(ctx, fmt.Sprintf(
			"\U0001f634 **%s** stopped automatically after %s with no players.",
			d.DisplayName, idleDuration,
		))
	}
}
