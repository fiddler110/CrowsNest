// Package exclusivity enforces CrowsNest's "at most MaxActive games
// running at a time" guarantee (one by default): starting a game while another is active is refused with
// a typed conflict instead of racing two containers up together, and
// switching between games is a single serialized stop-then-start
// operation.
package exclusivity

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

const (
	defaultStopPollInterval = 500 * time.Millisecond
	defaultStopPollTimeout  = 30 * time.Second

	// defaultStartTimeout bounds one background start, including a first
	// run's image pull (several GB for some game images).
	defaultStartTimeout = 30 * time.Minute

	// cancelWait bounds how long Stop waits for a cancelled in-flight start
	// to unwind before stopping the container.
	cancelWait = 15 * time.Second
)

// notifyTimeout bounds one notification so a slow webhook can't pile up
// goroutines; notifications are best-effort and never affect the action.
const notifyTimeout = 5 * time.Second

// maxNotifyErrLen is how much of a failed start's error text a notification
// carries (the tail, where docker/compose put the actual cause).
const maxNotifyErrLen = 200

// Notifier reports a message about a user-driven event. Same shape as
// idleshutdown.Notifier and satisfied by *notify.Discord; optional.
type Notifier interface {
	Notify(ctx context.Context, message string)
}

type actorKey struct{}

// WithActor returns ctx carrying the name of the user requesting an action.
// Only calls made with an actor send a "manual action" notification, which
// is how idle/night auto-stops (which call Stop with a plain context and
// send their own, more specific message) avoid a duplicate "stopped" one.
func WithActor(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, actorKey{}, name)
}

func actorFrom(ctx context.Context) string {
	name, _ := ctx.Value(actorKey{}).(string)
	return name
}

// ConflictError means a start was refused because Active is already
// running or starting. Handlers surface this as HTTP 409.
type ConflictError struct {
	Active string   // first active game; what the UI offers to switch away from
	All    []string // every active game, in registry order
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("exclusivity: %s is already active", e.Active)
}

// CooldownError means a start was refused because id was stopped too
// recently. Handlers surface this as HTTP 429.
type CooldownError struct {
	Game      string
	Remaining time.Duration
}

func (e *CooldownError) Error() string {
	return fmt.Sprintf("exclusivity: %s was stopped recently; try again in %ds", e.Game, int(e.Remaining.Round(time.Second).Seconds()))
}

// StartResult is the outcome of the most recent background start of a game.
type StartResult struct {
	Err string    // empty on success
	At  time.Time // when the start finished
}

// pendingStart is a start that has been accepted and is running in the
// background (compose pull/create/start can take minutes).
type pendingStart struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// Manager serializes start/stop/switch across the registered games so at
// most MaxActive are ever running at a time. The zero value is not usable —
// build one with NewManager.
//
// Starts are asynchronous: RequestStart/ConfirmSwitch do every check
// synchronously (so conflicts and cooldowns are still returned to the
// caller), then run the actual docker/compose start in the background
// under BaseContext, not the caller's request context — a closed browser
// tab or a proxy timeout must not kill a half-finished image pull. A game
// whose start is still in flight counts as active for the limit.
type Manager struct {
	mu       sync.Mutex // serializes start/stop/switch decisions
	registry *games.Registry
	docker   *dockerctl.Client
	lastStop map[string]time.Time // guarded by mu

	stateMu sync.Mutex // guards pending and results; never held while waiting
	pending map[string]*pendingStart
	results map[string]StartResult
	wg      sync.WaitGroup

	// BaseContext is the parent of every background start; cancel it on
	// shutdown. Nil means context.Background().
	BaseContext context.Context

	// StartTimeout bounds one background start; zero means
	// defaultStartTimeout.
	StartTimeout time.Duration

	// StopPollInterval/StopPollTimeout bound how long ConfirmSwitch waits
	// for the stopped game to actually report offline before starting the
	// next one. Zero means use the package defaults; overridable for tests.
	StopPollInterval time.Duration
	StopPollTimeout  time.Duration

	// MaxActive is how many games may run at once; zero or less means 1
	// (the strict one-at-a-time guarantee). Hosts with headroom can raise it.
	MaxActive int

	// Notifier, when set, is told about user-initiated starts, stops and
	// switches and about failed background starts. Optional — nil disables
	// notifications. Delivery is asynchronous and best-effort.
	Notifier Notifier
}

// notify sends message in the background with a short timeout, so a slow or
// down webhook can never delay or fail the action being reported. Tracked by
// wg so Wait (tests, shutdown) also flushes pending notifications.
func (m *Manager) notify(message string) {
	if m.Notifier == nil {
		return
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
		defer cancel()
		m.Notifier.Notify(ctx, message)
	}()
}

func (m *Manager) displayName(id string) string {
	if d, ok := m.registry.Get(id); ok && d.DisplayName != "" {
		return d.DisplayName
	}
	return id
}

// shortErr collapses err text onto one line and keeps its tail, so a
// multi-line compose failure stays a readable one-line notification.
func shortErr(msg string) string {
	msg = strings.Join(strings.Fields(msg), " ")
	if r := []rune(msg); len(r) > maxNotifyErrLen {
		msg = "…" + string(r[len(r)-maxNotifyErrLen:])
	}
	return msg
}

func (m *Manager) maxActive() int {
	if m.MaxActive > 0 {
		return m.MaxActive
	}
	return 1
}

func NewManager(registry *games.Registry, docker *dockerctl.Client) *Manager {
	return &Manager{
		registry: registry,
		docker:   docker,
		lastStop: map[string]time.Time{},
		pending:  map[string]*pendingStart{},
		results:  map[string]StartResult{},
	}
}

func (m *Manager) baseContext() context.Context {
	if m.BaseContext != nil {
		return m.BaseContext
	}
	return context.Background()
}

func (m *Manager) startTimeout() time.Duration {
	if m.StartTimeout > 0 {
		return m.StartTimeout
	}
	return defaultStartTimeout
}

// Starting reports whether a background start of id is still in flight.
func (m *Manager) Starting(id string) bool {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	_, ok := m.pending[id]
	return ok
}

// LastStart returns the outcome of id's most recent finished background
// start, if any.
func (m *Manager) LastStart(id string) (StartResult, bool) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	r, ok := m.results[id]
	return r, ok
}

// Wait blocks until every background start launched so far has finished.
// Intended for tests and shutdown.
func (m *Manager) Wait() { m.wg.Wait() }

func (m *Manager) pollInterval() time.Duration {
	if m.StopPollInterval > 0 {
		return m.StopPollInterval
	}
	return defaultStopPollInterval
}

func (m *Manager) pollTimeout() time.Duration {
	if m.StopPollTimeout > 0 {
		return m.StopPollTimeout
	}
	return defaultStopPollTimeout
}

// ActiveGame returns the ID of the first registered game found to be
// online or starting, if any. A game whose status can't be determined
// right now makes the whole scan inconclusive (err set, ok false) rather
// than being silently treated as not active — callers that use this to
// gate starting another game must never take an inconclusive scan as "all
// clear", since that could let two game servers run at once.
func (m *Manager) ActiveGame(ctx context.Context) (id string, ok bool, err error) {
	all, err := m.ActiveGames(ctx)
	if err != nil || len(all) == 0 {
		return "", false, err
	}
	return all[0], true, nil
}

// ActiveGames returns every registered game that is online or starting, in
// registry order, with the same fail-closed error behavior as ActiveGame.
func (m *Manager) ActiveGames(ctx context.Context) ([]string, error) {
	var active []string
	for _, d := range m.registry.All() {
		if m.Starting(d.ID) {
			// Accepted but still pulling/creating: the container may not
			// even exist yet, so a status check would say offline.
			active = append(active, d.ID)
			continue
		}
		if d.Status == nil {
			continue
		}
		status, err := d.Status.Check(ctx, d.ContainerName)
		if err != nil {
			return nil, fmt.Errorf("exclusivity: check %s status: %w", d.ID, err)
		}
		if status == games.StatusOnline || status == games.StatusStarting {
			active = append(active, d.ID)
		}
	}
	return active, nil
}

// RequestStart accepts a start of id and runs it in the background,
// refusing with a *ConflictError if the active-game limit is already
// reached by other games, or a *CooldownError if id was stopped too
// recently. Starting an already-active game is not a conflict. A nil
// return means the start was accepted, not that it finished — see
// Starting and LastStart. Safe to call concurrently.
func (m *Manager) RequestStart(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.startLocked(ctx, id, true)
}

// startLocked is RequestStart's body; announce is false when the caller
// (a switch) reports the whole operation itself.
func (m *Manager) startLocked(ctx context.Context, id string, announce bool) error {
	target, ok := m.registry.Get(id)
	if !ok {
		return fmt.Errorf("exclusivity: unknown game %q", id)
	}
	active, err := m.ActiveGames(ctx)
	if err != nil {
		// Can't rule out that other games are active right now — refuse to
		// start rather than risk exceeding the limit.
		return fmt.Errorf("exclusivity: cannot confirm no other game is active: %w", err)
	}
	alreadyActive := false
	for _, a := range active {
		if a == id {
			alreadyActive = true
		}
	}
	if !alreadyActive && len(active) >= m.maxActive() {
		return &ConflictError{Active: active[0], All: active}
	}
	if alreadyActive {
		// Already running, starting on its own, or a start is in flight:
		// nothing to do. (Re-running compose up on a running container
		// could recreate it if its config changed — not what Start means.)
		return nil
	}
	if target.RestartCooldown > 0 {
		if rem := m.cooldownRemaining(ctx, target); rem > 0 {
			return &CooldownError{Game: id, Remaining: rem}
		}
	}
	m.launchStart(target, actorFrom(ctx), announce)
	return nil
}

// cooldownRemaining is how much of d's RestartCooldown is left, measured
// from the later of the last panel stop and the container's own
// State.FinishedAt — so a crash, an external `docker stop`, or a stop from
// before a CrowsNest restart all count too.
func (m *Manager) cooldownRemaining(ctx context.Context, d games.GameDef) time.Duration {
	last := m.lastStop[d.ID]
	if fin, err := m.docker.FinishedAt(ctx, d.ContainerName); err == nil && fin.After(last) {
		last = fin
	}
	if last.IsZero() {
		return 0
	}
	return d.RestartCooldown - time.Since(last)
}

// launchStart runs target's docker/compose start in the background. Caller
// holds m.mu. actor is who asked (may be empty); announce says whether to
// notify on success — a switch announces itself, so its start stays quiet.
// A failure is always reported.
func (m *Manager) launchStart(target games.GameDef, actor string, announce bool) {
	ctx, cancel := context.WithTimeout(m.baseContext(), m.startTimeout())
	p := &pendingStart{cancel: cancel, done: make(chan struct{})}

	m.stateMu.Lock()
	m.pending[target.ID] = p
	delete(m.results, target.ID)
	m.stateMu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer close(p.done)
		defer cancel()

		err := m.docker.Start(ctx, target.DockerTarget())
		res := StartResult{At: time.Now()}
		switch {
		case err == nil:
			log.Printf("exclusivity: %s started", target.ID)
			if announce && actor != "" {
				m.notify(fmt.Sprintf("**%s** is starting (requested by %s).", target.DisplayName, actor))
			}
		case errors.Is(ctx.Err(), context.Canceled):
			log.Printf("exclusivity: start of %s cancelled", target.ID)
		default:
			log.Printf("exclusivity: start %s failed: %v", target.ID, err)
			res.Err = err.Error()
			msg := fmt.Sprintf("**%s** failed to start", target.DisplayName)
			if actor != "" {
				msg += " (requested by " + actor + ")"
			}
			m.notify(msg + ": " + shortErr(res.Err))
		}

		m.stateMu.Lock()
		// Only clean up our own entry: if Stop gave up waiting on us and a
		// newer start has since replaced it, leave that one alone.
		if m.pending[target.ID] == p {
			delete(m.pending, target.ID)
			m.results[target.ID] = res
		}
		m.stateMu.Unlock()
	}()
}

// Stop stops id. No conflict is possible — stopping is always safe. When
// ctx carries an actor (see WithActor) a successful stop is announced; a
// plain ctx (idle/night auto-stop) is not, since those notify themselves.
func (m *Manager) Stop(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.stopLocked(ctx, id); err != nil {
		return err
	}
	if actor := actorFrom(ctx); actor != "" {
		m.notify(fmt.Sprintf("**%s** was stopped by %s.", m.displayName(id), actor))
	}
	return nil
}

func (m *Manager) stopLocked(ctx context.Context, id string) error {
	d, ok := m.registry.Get(id)
	if !ok {
		return fmt.Errorf("exclusivity: unknown game %q", id)
	}
	cancelled := m.cancelPending(id)
	if err := m.docker.Stop(ctx, d.ContainerName); err != nil {
		// Stopping a start that was still pulling the image: compose never
		// created the container, so there is nothing to stop — that's a
		// successful stop, not an error.
		if !cancelled {
			return err
		}
		if exists, xerr := m.docker.Exists(ctx, d.ContainerName); xerr != nil || exists {
			return err
		}
	}
	m.lastStop[id] = time.Now()
	return nil
}

// cancelPending aborts an in-flight background start of id, if any, and
// waits (bounded) for it to unwind so it can't bring the container up
// after the stop that follows. It reports whether there was one.
func (m *Manager) cancelPending(id string) bool {
	m.stateMu.Lock()
	p, ok := m.pending[id]
	m.stateMu.Unlock()
	if !ok {
		return false
	}
	p.cancel()
	select {
	case <-p.done:
	case <-time.After(cancelWait):
		log.Printf("exclusivity: cancelled start of %s did not finish within %s; dropping it", id, cancelWait)
		m.stateMu.Lock()
		if m.pending[id] == p {
			delete(m.pending, id)
		}
		m.stateMu.Unlock()
	}
	return true
}

// ConfirmSwitch stops `from`, waits (bounded) for it to actually report
// offline, then starts `to`. Serialized by the same lock as
// RequestStart/Stop so two concurrent requests (two browser tabs) can't
// race into both containers running at once.
func (m *Manager) ConfirmSwitch(ctx context.Context, from, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	fromDef, ok := m.registry.Get(from)
	if !ok {
		return fmt.Errorf("exclusivity: unknown game %q", from)
	}
	if err := m.stopLocked(ctx, from); err != nil {
		return fmt.Errorf("exclusivity: stop %s: %w", from, err)
	}
	if err := m.waitOffline(ctx, fromDef); err != nil {
		return err
	}
	if err := m.startLocked(ctx, to, false); err != nil {
		return err
	}
	if actor := actorFrom(ctx); actor != "" {
		m.notify(fmt.Sprintf("%s switched from **%s** to **%s**.", actor, fromDef.DisplayName, m.displayName(to)))
	}
	return nil
}

func (m *Manager) waitOffline(ctx context.Context, d games.GameDef) error {
	if d.Status == nil {
		return nil
	}
	deadline := time.Now().Add(m.pollTimeout())
	ticker := time.NewTicker(m.pollInterval())
	defer ticker.Stop()

	for {
		status, err := d.Status.Check(ctx, d.ContainerName)
		if err == nil && status == games.StatusOffline {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("exclusivity: timed out waiting for %s to stop", d.ID)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
