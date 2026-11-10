// Package statehub observes every registered game from one place. A Hub runs
// one observer goroutine per game: it checks the game's status (docker
// inspect) and, when the game could be up, asks its PlayerCounter, on a
// cadence that follows what the game is doing — fast while it is starting or
// stopping, slower while online, slowest while offline. Everything else that
// used to poll on its own (the dashboard, player join/leave announcements,
// idle and night shutdown) reads the hub's latest observation instead, and
// subscribers are told when an observation changes.
package statehub

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
)

// Default cadences.
const (
	DefaultBusyInterval      = 2 * time.Second  // starting or stopping
	DefaultOnlineInterval    = 10 * time.Second // online
	DefaultIdleInterval      = 30 * time.Second // offline or unknown
	DefaultReconcileInterval = 5 * time.Second  // registry re-read (managed games come and go)
	DefaultProbeTimeout      = 20 * time.Second // bounds one observation
)

// Observation is one game's state as its StatusChecker and PlayerCounter
// reported it at the same moment. Status is StatusUnknown when the check
// failed. Players are only asked for when the game is online or unknown, so
// an offline or booting game doesn't cost a failing call; PlayersOK is false
// whenever no count was read.
type Observation struct {
	Status    games.Status
	Count     int
	Names     []string
	PlayersOK bool
	At        time.Time
}

// same reports whether o and p describe the same state (At aside).
func (o Observation) same(p Observation) bool {
	return o.Status == p.Status && o.Count == p.Count && o.PlayersOK == p.PlayersOK && slices.Equal(o.Names, p.Names)
}

// Probe observes d once, directly: what an observer does on each tick, and
// the fallback for callers without a Hub.
func Probe(ctx context.Context, d games.GameDef) Observation {
	o := Observation{Status: games.StatusUnknown}
	if d.Status != nil {
		if st, err := d.Status.Check(ctx, d.ContainerName); err == nil {
			o.Status = st
		}
	}
	if d.Players != nil && (o.Status == games.StatusOnline || o.Status == games.StatusUnknown) {
		o.Count, o.Names, o.PlayersOK = d.Players.PlayerCount(ctx)
		o.Names = slices.Clone(o.Names)
	}
	return o
}

// Hub owns the observers. Set the optional fields before Run; the zero value
// of each means its default.
type Hub struct {
	registry *games.Registry

	// Busy reports whether a game is starting or stopping (wired to the
	// exclusivity manager); such a game is observed at BusyInterval. A flip
	// of Busy is itself a change subscribers hear about.
	Busy func(id string) bool

	BusyInterval, OnlineInterval, IdleInterval time.Duration
	ReconcileInterval                          time.Duration
	ProbeTimeout                               time.Duration

	// Now and After override the clock (tests).
	Now   func() time.Time
	After func(time.Duration) <-chan time.Time

	mu        sync.Mutex
	games     map[string]*entry
	subs      map[*Subscription]struct{}
	version   uint64
	running   bool
	ctx       context.Context
	wg        sync.WaitGroup
	reconcile chan struct{}
}

// entry is one game's observer and latest observation. Guarded by Hub.mu.
type entry struct {
	obs     Observation
	has     bool
	busy    bool
	started uint64        // observations begun
	done    uint64        // the started-count of the latest stored observation
	want    uint64        // Current waits until done >= want (set by Poke)
	updated chan struct{} // closed and replaced on every stored observation, and when the observer exits
	exited  bool          // the observer has returned
	poke    chan struct{} // buffered(1): observe now
	cancel  context.CancelFunc
}

// New builds a Hub over registry. Call Run to start observing.
func New(registry *games.Registry) *Hub {
	return &Hub{
		registry:  registry,
		games:     map[string]*entry{},
		subs:      map[*Subscription]struct{}{},
		reconcile: make(chan struct{}, 1),
	}
}

func (h *Hub) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Hub) after(d time.Duration) <-chan time.Time {
	if h.After != nil {
		return h.After(d)
	}
	return time.After(d)
}

func or(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func (h *Hub) busy(id string) bool { return h.Busy != nil && h.Busy(id) }

// Run starts one observer per registered game, keeps that set in step with
// the registry, and returns once ctx is cancelled and every observer has
// stopped.
func (h *Hub) Run(ctx context.Context) {
	h.mu.Lock()
	h.running, h.ctx = true, ctx
	h.mu.Unlock()
	for {
		h.Reconcile()
		select {
		case <-ctx.Done():
			h.mu.Lock()
			h.running = false
			for _, e := range h.games {
				e.cancel()
			}
			h.mu.Unlock()
			h.wg.Wait()
			return
		case <-h.reconcile:
		case <-h.after(or(h.ReconcileInterval, DefaultReconcileInterval)):
		}
	}
}

// Reconcile starts observers for newly registered games and stops those of
// removed ones (their observations are dropped). Run calls it on its own;
// it is exported for tests.
func (h *Hub) Reconcile() {
	defs := h.registry.All()
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.running {
		return
	}
	seen := make(map[string]bool, len(defs))
	changed := false
	for _, d := range defs {
		seen[d.ID] = true
		if _, ok := h.games[d.ID]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(h.ctx)
		e := &entry{updated: make(chan struct{}), poke: make(chan struct{}, 1), cancel: cancel}
		h.games[d.ID] = e
		h.wg.Add(1)
		go h.observe(ctx, d.ID, e)
	}
	for id, e := range h.games {
		if !seen[id] {
			e.cancel()
			delete(h.games, id)
			changed = true
		}
	}
	if changed {
		h.bumpLocked()
	}
}

// observe is one game's observer loop.
func (h *Hub) observe(ctx context.Context, id string, e *entry) {
	defer h.wg.Done()
	defer func() {
		h.mu.Lock()
		e.exited = true
		close(e.updated)
		h.mu.Unlock()
	}()
	for {
		d, ok := h.registry.Get(id)
		if !ok {
			return // removed; Reconcile drops the entry
		}
		h.mu.Lock()
		e.started++
		seq := e.started
		h.mu.Unlock()

		pctx, cancel := context.WithTimeout(ctx, or(h.ProbeTimeout, DefaultProbeTimeout))
		o := Probe(pctx, d)
		cancel()
		if ctx.Err() != nil {
			return
		}
		o.At = h.now()
		busy := h.busy(id)
		h.store(id, e, seq, o, busy)

		var wait time.Duration
		switch {
		case busy:
			wait = or(h.BusyInterval, DefaultBusyInterval)
		case o.Status == games.StatusOnline:
			wait = or(h.OnlineInterval, DefaultOnlineInterval)
		default:
			wait = or(h.IdleInterval, DefaultIdleInterval)
		}
		select {
		case <-ctx.Done():
			return
		case <-e.poke:
		case <-h.after(wait):
		}
	}
}

func (h *Hub) store(id string, e *entry, seq uint64, o Observation, busy bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.games[id] != e {
		return // removed meanwhile
	}
	changed := !e.has || !e.obs.same(o) || e.busy != busy
	e.obs, e.has, e.busy, e.done = o, true, busy, seq
	close(e.updated)
	e.updated = make(chan struct{})
	if changed {
		h.bumpLocked()
	}
}

// Get returns id's latest observation without blocking, however old, and
// whether there is one.
func (h *Hub) Get(id string) (Observation, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := h.games[id]; e != nil && e.has {
		return e.obs, true
	}
	return Observation{}, false
}

// Current returns d's observation for a request that needs one now: the
// latest, unless none exists yet or a Poke asked for a fresher one, in which
// case it waits (bounded by ctx) for the observer. A game the hub has no
// observer for (not running, or registered since the last reconcile) is
// probed directly.
func (h *Hub) Current(ctx context.Context, d games.GameDef) Observation {
	h.mu.Lock()
	e := h.games[d.ID]
	if e == nil {
		h.mu.Unlock()
		h.signalReconcile()
		return Probe(ctx, d)
	}
	for !e.has || e.done < e.want {
		if e.exited {
			h.mu.Unlock()
			return Probe(ctx, d)
		}
		ch := e.updated
		h.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return Observation{Status: games.StatusUnknown}
		}
		h.mu.Lock()
	}
	o := e.obs
	h.mu.Unlock()
	return o
}

// Fresh pokes d and waits for the resulting observation (see Current). For
// decisions that must not act on a reading up to one cadence old, such as an
// automatic stop.
func (h *Hub) Fresh(ctx context.Context, d games.GameDef) Observation {
	h.Poke(d.ID)
	return h.Current(ctx, d)
}

// Poke asks id's observer to observe now. Pokes coalesce, never block, and
// make Current wait for an observation begun after the poke. Poking an
// unknown id prompts a reconcile (a game may just have been registered).
func (h *Hub) Poke(id string) {
	h.mu.Lock()
	e := h.games[id]
	if e != nil {
		e.want = e.started + 1
		select {
		case e.poke <- struct{}{}:
		default:
		}
	}
	h.mu.Unlock()
	if e == nil {
		h.signalReconcile()
	}
}

func (h *Hub) signalReconcile() {
	select {
	case h.reconcile <- struct{}{}:
	default:
	}
}

// Signal tells subscribers something changed outside any observation (for
// instance a start's recorded result), without observing anything.
func (h *Hub) Signal() {
	h.mu.Lock()
	h.bumpLocked()
	h.mu.Unlock()
}

// Version counts changes; it increases whenever subscribers are notified.
func (h *Hub) Version() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.version
}

func (h *Hub) bumpLocked() {
	h.version++
	for s := range h.subs {
		select {
		case s.c <- struct{}{}:
		default: // already pending: the subscriber will re-read anyway
		}
	}
}

// Subscription receives a value on C after each change (coalesced: one
// pending value at most, so a slow reader never blocks the observers).
// Readers re-read state with Get. Close it when done.
type Subscription struct {
	C <-chan struct{}
	c chan struct{}
	h *Hub
}

// Subscribe registers a change subscriber.
func (h *Hub) Subscribe() *Subscription {
	c := make(chan struct{}, 1)
	s := &Subscription{C: c, c: c, h: h}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

// Close unregisters s.
func (s *Subscription) Close() {
	s.h.mu.Lock()
	delete(s.h.subs, s)
	s.h.mu.Unlock()
}
