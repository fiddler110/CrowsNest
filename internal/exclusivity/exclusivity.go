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
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/history"
	"github.com/fiddler110/crowsnest/internal/memadmit"
	"github.com/fiddler110/crowsnest/internal/notify"
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

// prepareStopTimeout bounds a game's pre-stop warning and save.
const prepareStopTimeout = 30 * time.Second

// notifyTimeout bounds one notification so a slow webhook can't pile up
// goroutines; notifications are best-effort and never affect the action.
const notifyTimeout = 5 * time.Second

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

// MemoryAdmitter decides whether the host has the memory for a start; satisfied
// by *memadmit.Budget. claimed is what other starting games are still to take,
// freed what a game being stopped for this start gives back.
type MemoryAdmitter interface {
	Need(id string) (bytes uint64, measured bool)
	Admit(id string, claimed, freed uint64) error
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

// BusyError means a start was refused because id is being stopped right now.
// Handlers surface this as HTTP 409 with busy=true (distinct from a limit
// conflict, which offers a switch).
type BusyError struct{ Game string }

func (e *BusyError) Error() string {
	return fmt.Sprintf("exclusivity: %s is still stopping; try again once it has stopped", e.Game)
}

// StartResult is the outcome of the most recent background operation (start,
// stop or switch) that finished for a game. Err is prefixed with the
// operation when it wasn't a plain start.
type StartResult struct {
	Err    string    // empty on success; safe to show every user
	Detail string    // raw error text (may hold docker/compose stderr); admins and the log only
	At     time.Time // when the operation finished
}

// publicFailure builds the user-facing text for a failed operation: prefix
// plus a generic phrase, since raw docker/compose output can leak paths and
// config. Cooldown and busy errors are already safe and pass through.
func publicFailure(prefix string, err error) string {
	var cd *CooldownError
	var busy *BusyError
	var mem *memadmit.Error
	if errors.As(err, &cd) || errors.As(err, &busy) || errors.As(err, &mem) {
		return prefix + err.Error()
	}
	return prefix + "see the CrowsNest log for details"
}

// pendingStop is a stop (or the stop half of a switch) in progress. err is
// written before done is closed.
type pendingStop struct {
	done chan struct{}
	err  error
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
	mu       sync.Mutex // serializes start/stop/switch decisions; never held across a docker stop
	registry *games.Registry
	docker   *dockerctl.Client

	stateMu  sync.Mutex // guards the fields below; never held while waiting
	lastStop map[string]time.Time
	pending  map[string]*pendingStart
	stopping map[string]*pendingStop
	incoming map[string]bool // switch targets reserved while their predecessor stops
	results  map[string]StartResult
	wg       sync.WaitGroup

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

	// MaxActiveFunc, when set, is consulted instead of MaxActive each time
	// the limit is checked, so it can change at runtime.
	MaxActiveFunc func() int

	// CooldownFunc, when set, overrides a game's restart cooldown (from its
	// module) at each start. ok is false when the game has no override; a
	// zero duration with ok turns the cooldown off.
	CooldownFunc func(id string) (time.Duration, bool)

	// Memory, when set, refuses a start the host has no memory for, on top
	// of the active-game limit. Optional: nil means only the limit applies.
	Memory MemoryAdmitter

	// Notifier, when set, is told about user-initiated starts, stops and
	// switches and about failed background starts. Optional — nil disables
	// notifications. Delivery is asynchronous and best-effort.
	Notifier Notifier

	// Backups, when set, takes the backup of games configured with
	// backup.before_stop, between the pre-stop save and the stop itself.
	Backups Backuper

	// History, when set, records user-initiated starts, stops and switches
	// and failed operations in the activity log. Automatic stops record
	// themselves (idle/night), so only calls with an actor are logged here.
	History history.Recorder

	// OnChange, when set, is called with a game's ID whenever what Starting,
	// Stopping or LastStart report for it changes. It is called with the
	// decision lock possibly held, so it must not block or call back into
	// the Manager's actions (wired to the state hub's Poke/Signal).
	OnChange func(id string)
}

func (m *Manager) changed(id string) {
	if m.OnChange != nil {
		m.OnChange(id)
	}
}

func (m *Manager) record(kind, game, actor, detail string) {
	if m.History != nil {
		m.History.Record(kind, game, actor, detail)
	}
}

// Backuper runs a game's backup; satisfied by *backup.Manager.
type Backuper interface {
	RunBackup(ctx context.Context, d games.GameDef, actor string) error
}

// notify sends message in the background with a short timeout, so a slow or
// down webhook can never delay or fail the action being reported. Tracked by
// wg so Wait (tests, shutdown) also flushes pending notifications.
func (m *Manager) notify(game, message string) {
	if m.Notifier == nil {
		return
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
		defer cancel()
		m.Notifier.Notify(notify.WithGame(ctx, game), message)
	}()
}

func (m *Manager) displayName(id string) string {
	if d, ok := m.registry.Get(id); ok && d.DisplayName != "" {
		return d.DisplayName
	}
	return id
}

func (m *Manager) maxActive() int {
	if m.MaxActiveFunc != nil {
		if n := m.MaxActiveFunc(); n > 0 {
			return n
		}
	}
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
		stopping: map[string]*pendingStop{},
		incoming: map[string]bool{},
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

// Stopping reports whether a stop of id is in progress.
func (m *Manager) Stopping(id string) bool {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	_, ok := m.stopping[id]
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
	return m.activeGames(ctx, "")
}

// activeGames is ActiveGames, except a switch reservation for skipIncoming is
// not counted (the switch is asking to start exactly that game).
func (m *Manager) activeGames(ctx context.Context, skipIncoming string) ([]string, error) {
	var active []string
	for _, d := range m.registry.All() {
		if m.Starting(d.ID) || m.isIncoming(d.ID, skipIncoming) {
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

func (m *Manager) isIncoming(id, skip string) bool {
	if id == skip {
		return false
	}
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	return m.incoming[id]
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
	return m.startLocked(ctx, id, true, "")
}

// startLocked is RequestStart's body; announce is false when the caller
// (a switch) reports the whole operation itself.
func (m *Manager) startLocked(ctx context.Context, id string, announce bool, switchTarget string) error {
	target, ok := m.registry.Get(id)
	if !ok {
		return fmt.Errorf("exclusivity: unknown game %q", id)
	}
	if m.Stopping(id) {
		return &BusyError{Game: id}
	}
	active, err := m.activeGames(ctx, switchTarget)
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
	if m.cooldownOf(target) > 0 {
		if rem := m.cooldownRemaining(ctx, target); rem > 0 {
			return &CooldownError{Game: id, Remaining: rem}
		}
	}
	if err := m.admitMemory(id, ""); err != nil {
		return err
	}
	m.launchStart(target, actorFrom(ctx), announce)
	return nil
}

// admitMemory asks the memory budget whether id fits. Other games whose start
// is in flight count as still to take their memory; stopping is the game a
// switch is stopping, whose memory is about to be free.
func (m *Manager) admitMemory(id, stopping string) error {
	if m.Memory == nil {
		return nil
	}
	var claimed, freed uint64
	m.stateMu.Lock()
	for other := range m.pending {
		if other != id {
			n, _ := m.Memory.Need(other)
			claimed += n
		}
	}
	m.stateMu.Unlock()
	if stopping != "" {
		freed, _ = m.Memory.Need(stopping)
	}
	return m.Memory.Admit(id, claimed, freed)
}

// cooldownOf is d's restart cooldown: the CooldownFunc override when it has
// one, else the game's own.
func (m *Manager) cooldownOf(d games.GameDef) time.Duration {
	if m.CooldownFunc != nil {
		if c, ok := m.CooldownFunc(d.ID); ok {
			return c
		}
	}
	return d.RestartCooldown
}

// cooldownRemaining is how much of d's restart cooldown is left, measured
// from the later of the last panel stop and the container's own
// State.FinishedAt — so a crash, an external `docker stop`, or a stop from
// before a CrowsNest restart all count too.
func (m *Manager) cooldownRemaining(ctx context.Context, d games.GameDef) time.Duration {
	m.stateMu.Lock()
	last := m.lastStop[d.ID]
	m.stateMu.Unlock()
	if fin, err := m.docker.FinishedAt(ctx, d.ContainerName); err == nil && fin.After(last) {
		last = fin
	}
	if last.IsZero() {
		return 0
	}
	return m.cooldownOf(d) - time.Since(last)
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
	m.changed(target.ID)

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer close(p.done)
		defer cancel()

		dt := target.DockerTarget()
		err := m.docker.Start(ctx, dt)
		res := StartResult{At: time.Now()}
		switch {
		case err == nil:
			log.Printf("exclusivity: %s started", target.ID)
			if actor != "" {
				m.record(history.KindStart, target.ID, actor, "")
			}
			if announce && actor != "" {
				m.notify(target.ID, fmt.Sprintf("**%s** is starting (requested by %s).", target.DisplayName, actor))
			}
		case errors.Is(ctx.Err(), context.Canceled):
			log.Printf("exclusivity: start of %s cancelled", target.ID)
		default:
			log.Printf("exclusivity: start %s failed: %v", target.ID, err)
			res.Detail = err.Error()
			res.Err = publicFailure("", err)
			m.record(history.KindStartFailed, target.ID, actor, res.Err)
			msg := fmt.Sprintf("**%s** failed to start", target.DisplayName)
			if actor != "" {
				msg += " (requested by " + actor + ")"
			}
			m.notify(target.ID, msg+": "+res.Err)
		}

		m.stateMu.Lock()
		// Only clean up our own entry: if Stop gave up waiting on us and a
		// newer start has since replaced it, leave that one alone.
		if m.pending[target.ID] == p {
			delete(m.pending, target.ID)
			m.results[target.ID] = res
		}
		m.stateMu.Unlock()
		m.changed(target.ID)
	}()
}

// Stop stops id and waits for it to finish. No conflict is possible —
// stopping is always safe. When ctx carries an actor (see WithActor) a
// successful stop is announced; a plain ctx (idle/night auto-stop) is not,
// since those notify themselves. The decision lock is held only to register
// the stop, never across `docker stop`, so other games stay controllable
// while a slow save runs. Use RequestStop for the non-blocking form.
func (m *Manager) Stop(ctx context.Context, id string) error {
	d, ok := m.registry.Get(id)
	if !ok {
		return fmt.Errorf("exclusivity: unknown game %q", id)
	}
	m.mu.Lock()
	p, owner := m.beginStop(id)
	m.mu.Unlock()
	if err := m.finishOrJoinStop(ctx, d, p, owner); err != nil {
		return err
	}
	if actor := actorFrom(ctx); actor != "" {
		m.record(history.KindStop, id, actor, "")
		m.notify(id, fmt.Sprintf("**%s** was stopped by %s.", m.displayName(id), actor))
	}
	return nil
}

// RequestStop accepts a stop of id and runs it in the background under
// BaseContext (a closed tab or a proxy timeout must not interrupt a save in
// progress). A nil return means accepted; see Stopping and LastStart for the
// outcome. A failure is recorded and notified.
func (m *Manager) RequestStop(ctx context.Context, id string) error {
	d, ok := m.registry.Get(id)
	if !ok {
		return fmt.Errorf("exclusivity: unknown game %q", id)
	}
	actor := actorFrom(ctx)
	m.mu.Lock()
	p, owner := m.beginStop(id)
	m.mu.Unlock()
	if !owner {
		return nil // already stopping
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		err := m.finishOrJoinStop(m.baseContext(), d, p, true)
		if err != nil {
			log.Printf("exclusivity: stop %s failed: %v", id, err)
			m.recordFailure(id, publicFailure("stop failed: ", err), "stop failed: "+err.Error())
			m.record(history.KindStopFailed, id, actor, publicFailure("", err))
			m.notify(d.ID, fmt.Sprintf("**%s** failed to stop: %s", d.DisplayName, publicFailure("", err)))
			return
		}
		if actor != "" {
			m.record(history.KindStop, id, actor, "")
			m.notify(d.ID, fmt.Sprintf("**%s** was stopped by %s.", d.DisplayName, actor))
		}
	}()
	return nil
}

func (m *Manager) recordFailure(id, msg, detail string) {
	m.stateMu.Lock()
	m.results[id] = StartResult{Err: msg, Detail: detail, At: time.Now()}
	m.stateMu.Unlock()
	m.changed(id)
}

// beginStop registers a stop of id. owner is true when the caller must run
// it (finishOrJoinStop); false means one is already running and p is it.
// Caller holds m.mu, which orders this against startLocked so a start either
// precedes the stop (and is cancelled by it) or is refused while it runs.
func (m *Manager) beginStop(id string) (p *pendingStop, owner bool) {
	m.stateMu.Lock()
	if p, ok := m.stopping[id]; ok {
		m.stateMu.Unlock()
		return p, false
	}
	p = &pendingStop{done: make(chan struct{})}
	m.stopping[id] = p
	m.stateMu.Unlock()
	m.changed(id)
	return p, true
}

// finishOrJoinStop runs the stop when owner, else waits for the running one.
func (m *Manager) finishOrJoinStop(ctx context.Context, d games.GameDef, p *pendingStop, owner bool) error {
	if !owner {
		select {
		case <-p.done:
			return p.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	p.err = m.doStop(ctx, d)
	m.stateMu.Lock()
	delete(m.stopping, d.ID)
	m.stateMu.Unlock()
	close(p.done)
	m.changed(d.ID)
	return p.err
}

// doStop cancels any in-flight start of d and stops its container.
func (m *Manager) doStop(ctx context.Context, d games.GameDef) error {
	cancelled := m.cancelPending(d.ID)
	m.prepareStop(ctx, d)
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
	m.stateMu.Lock()
	m.lastStop[d.ID] = time.Now()
	m.stateMu.Unlock()
	return nil
}

// prepareStop gives the game its chance to warn players and save before the
// container is stopped. Best-effort and time-boxed: a game that isn't up
// (or whose API is down) must never hold up or fail a stop.
func (m *Manager) prepareStop(ctx context.Context, d games.GameDef) {
	wantBackup := d.Backup != nil && d.Backup.BeforeStop && m.Backups != nil
	if d.PreStop == nil && !wantBackup {
		return
	}
	if up, err := m.docker.Running(ctx, d.ContainerName); err != nil || !up {
		return
	}
	if d.PreStop != nil {
		pctx, cancel := context.WithTimeout(ctx, prepareStopTimeout)
		defer cancel()
		if err := d.PreStop.PrepareStop(pctx); err != nil {
			log.Printf("exclusivity: prepare stop of %s: %v (stopping anyway)", d.ID, err)
		}
	}
	// After the save, so the backup holds the world as it was just written;
	// before the stop, so an update-on-start pull always has a fresh one behind it.
	if wantBackup {
		if err := m.Backups.RunBackup(ctx, d, ""); err != nil {
			log.Printf("exclusivity: backup of %s before stop: %v (stopping anyway)", d.ID, err)
		}
	}
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
		m.changed(id)
	}
	return true
}

// switchOp is a reserved switch: `from` is stopping and `to` is held as
// active so nothing else can take its slot in between.
type switchOp struct {
	from, to games.GameDef
	p        *pendingStop
	owner    bool
}

// beginSwitch validates a switch and reserves it. Caller must pass the
// result to runSwitch exactly once.
func (m *Manager) beginSwitch(from, to string) (*switchOp, error) {
	fromDef, ok := m.registry.Get(from)
	if !ok {
		return nil, fmt.Errorf("exclusivity: unknown game %q", from)
	}
	toDef, ok := m.registry.Get(to)
	if !ok {
		return nil, fmt.Errorf("exclusivity: unknown game %q", to)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Stopping(to) {
		return nil, &BusyError{Game: to}
	}
	// Refuse before stopping anything: startLocked would reject the target
	// after `from` was already down, leaving nothing running.
	if m.cooldownOf(toDef) > 0 {
		if rem := m.cooldownRemaining(context.Background(), toDef); rem > 0 {
			return nil, &CooldownError{Game: to, Remaining: rem}
		}
	}
	// Likewise for memory: the target must fit once the source is down.
	if err := m.admitMemory(to, from); err != nil {
		return nil, err
	}
	m.stateMu.Lock()
	m.incoming[to] = true
	m.stateMu.Unlock()
	op := &switchOp{from: fromDef, to: toDef}
	op.p, op.owner = m.beginStop(from)
	return op, nil
}

// runSwitch stops the source, waits (bounded) for it to report offline, then
// starts the target.
func (m *Manager) runSwitch(ctx context.Context, op *switchOp) error {
	release := func() {
		m.stateMu.Lock()
		delete(m.incoming, op.to.ID)
		m.stateMu.Unlock()
	}
	if err := m.finishOrJoinStop(ctx, op.from, op.p, op.owner); err != nil {
		release()
		return fmt.Errorf("exclusivity: stop %s: %w", op.from.ID, err)
	}
	if err := m.waitOffline(ctx, op.from); err != nil {
		release()
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	release() // under mu: nobody can slip in between release and the start
	if err := m.startLocked(ctx, op.to.ID, false, ""); err != nil {
		return err
	}
	if actor := actorFrom(ctx); actor != "" {
		m.record(history.KindStop, op.from.ID, actor, "switching to "+op.to.DisplayName)
		m.notify(op.to.ID, fmt.Sprintf("%s switched from **%s** to **%s**.", actor, op.from.DisplayName, op.to.DisplayName))
	}
	return nil
}

// ConfirmSwitch stops `from`, waits (bounded) for it to actually report
// offline, then starts `to`, blocking until the start has been accepted. The
// target is reserved for the duration, so two concurrent requests (two
// browser tabs) can't race into exceeding the limit. Use RequestSwitch for
// the non-blocking form.
func (m *Manager) ConfirmSwitch(ctx context.Context, from, to string) error {
	op, err := m.beginSwitch(from, to)
	if err != nil {
		return err
	}
	return m.runSwitch(ctx, op)
}

// RequestSwitch reserves a switch and runs it in the background under
// BaseContext. Validation errors return synchronously; a failure later is
// recorded against the target (see LastStart) and notified.
func (m *Manager) RequestSwitch(ctx context.Context, from, to string) error {
	op, err := m.beginSwitch(from, to)
	if err != nil {
		return err
	}
	bg := WithActor(m.baseContext(), actorFrom(ctx))
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := m.runSwitch(bg, op); err != nil {
			log.Printf("exclusivity: switch %s->%s failed: %v", op.from.ID, op.to.ID, err)
			pre := "switch from " + op.from.DisplayName + " failed: "
			m.recordFailure(op.to.ID, publicFailure(pre, err), pre+err.Error())
			m.record(history.KindStartFailed, op.to.ID, actorFrom(bg), publicFailure("switch from "+op.from.DisplayName+": ", err))
			m.notify(op.to.ID, fmt.Sprintf("Switch from **%s** to **%s** failed: %s", op.from.DisplayName, op.to.DisplayName, publicFailure("", err)))
		}
	}()
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
