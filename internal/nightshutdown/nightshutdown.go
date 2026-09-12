// Package nightshutdown stops an online, empty game during a configured
// nightly time window — a direct port of the original Python CrowsNest's
// APScheduler-based night-shutdown job (app.py lines ~774-916), generalized
// to every registered game and re-checked on a plain ticker instead of a
// cron schedule (Go's stdlib has no cron primitive, and a ticker gives the
// same "check every N minutes within the window" behavior without pulling
// in a scheduling library).
//
// This is deliberately independent of internal/idleshutdown: night-shutdown
// stops on the spot the moment a check inside the window finds the game
// empty, with no grace period, since the whole point is "don't let it run
// unattended overnight" rather than "give it a few minutes in case someone
// comes back." A game can be covered by both, neither, or either alone.
package nightshutdown

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
)

// Stopper stops a registered game by ID — satisfied directly by
// *exclusivity.Manager, same interface shape as idleshutdown.Stopper (kept
// as its own type so this package doesn't depend on idleshutdown).
type Stopper interface {
	Stop(ctx context.Context, id string) error
}

// Notifier reports a message about a CrowsNest-initiated event. Satisfied
// by *notify.Discord; optional — a nil Notifier on Manager just skips
// notifying.
type Notifier interface {
	Notify(ctx context.Context, message string)
}

// Manager runs the night-shutdown check on a timer. Build one with New; the
// zero value is not usable.
type Manager struct {
	registry *games.Registry
	stopper  Stopper

	// StartHour/EndHour are 0-23, local to Loc. The window wraps midnight
	// when StartHour > EndHour.
	startHour, endHour int
	checkInterval      time.Duration
	loc                *time.Location

	// Notifier, when set, is told about every stop this manager triggers.
	Notifier Notifier

	// Now overrides time.Now. Intended for tests; production callers should
	// leave it unset.
	Now func() time.Time
}

// New builds a Manager that, every checkInterval, stops (via stopper) any
// registered, night-shutdown-eligible game that's online and empty while
// the current time in loc is within [startHour, endHour).
func New(registry *games.Registry, stopper Stopper, startHour, endHour int, checkInterval time.Duration, loc *time.Location) *Manager {
	return &Manager{
		registry:      registry,
		stopper:       stopper,
		startHour:     startHour,
		endHour:       endHour,
		checkInterval: checkInterval,
		loc:           loc,
	}
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) inWindow(t time.Time) bool {
	hour := t.In(m.loc).Hour()
	if m.startHour <= m.endHour {
		return hour >= m.startHour && hour < m.endHour
	}
	// Wraps midnight, e.g. 23 -> 5.
	return hour >= m.startHour || hour < m.endHour
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

// Tick checks every registered, night-shutdown-eligible game once, but only
// does anything while the current time is inside the configured window.
// Exported so Run's ticker and tests can both drive it directly.
func (m *Manager) Tick(ctx context.Context) {
	if !m.inWindow(m.now()) {
		return
	}
	for _, d := range m.registry.All() {
		if !d.NightShutdown {
			continue
		}
		m.checkGame(ctx, d)
	}
}

func (m *Manager) checkGame(ctx context.Context, d games.GameDef) {
	if d.Status == nil {
		return
	}
	status, err := d.Status.Check(ctx, d.ContainerName)
	if err != nil || status != games.StatusOnline {
		return // nothing to shut down if it's not confirmedly online
	}

	if d.Players == nil {
		return // can't tell who's connected -> never guess it's safe to stop
	}
	count, _, ok := d.Players.PlayerCount(ctx)
	if !ok {
		log.Printf("nightshutdown: %s player count unavailable — skipping for safety", d.ID)
		return
	}
	if count > 0 {
		return
	}

	now := m.now().In(m.loc)
	log.Printf("nightshutdown: stopping %s at %s with no players", d.ID, now.Format("15:04"))
	if err := m.stopper.Stop(ctx, d.ID); err != nil {
		log.Printf("nightshutdown: stop %s: %v", d.ID, err)
		return
	}
	if m.Notifier != nil {
		m.Notifier.Notify(ctx, fmt.Sprintf(
			"\U0001f319 **%s** is shutting down for the night (no players active at %s).",
			d.DisplayName, now.Format("15:04"),
		))
	}
}
