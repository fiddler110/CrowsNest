package statehub

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
)

type fakeStatus struct {
	mu    sync.Mutex
	s     games.Status
	calls int
}

func (f *fakeStatus) set(s games.Status) { f.mu.Lock(); f.s = s; f.mu.Unlock() }
func (f *fakeStatus) Check(context.Context, string) (games.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.s, nil
}

type fakePlayers struct {
	mu    sync.Mutex
	names []string
}

func (p *fakePlayers) set(n ...string) { p.mu.Lock(); p.names = n; p.mu.Unlock() }
func (p *fakePlayers) PlayerCount(context.Context) (int, []string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.names), p.names, true
}

// timer is one After call an observer made: how long it asked to wait, and
// the channel the test fires to end the wait.
type timer struct {
	d time.Duration
	c chan time.Time
}

// clock hands out observer timers to the test. The reconcile loop's
// (time.Hour in these tests) never fire.
type clock struct{ timers chan timer }

func (c *clock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	if d == time.Hour {
		return ch
	}
	c.timers <- timer{d, ch}
	return ch
}

// next waits for an observer to finish an observation and start waiting.
func (c *clock) next(t *testing.T) timer {
	t.Helper()
	select {
	case tm := <-c.timers:
		return tm
	case <-time.After(5 * time.Second):
		t.Fatal("no observer timer")
		return timer{}
	}
}

func (c *clock) none(t *testing.T) {
	t.Helper()
	select {
	case tm := <-c.timers:
		t.Fatalf("unexpected observer timer %v", tm.d)
	case <-time.After(30 * time.Millisecond):
	}
}

type rig struct {
	hub    *Hub
	reg    *games.Registry
	st     *fakeStatus
	pl     *fakePlayers
	clk    *clock
	busy   atomic.Bool
	cancel context.CancelFunc
	done   chan struct{}
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{st: &fakeStatus{s: games.StatusOffline}, pl: &fakePlayers{}, clk: &clock{timers: make(chan timer, 100)}}
	var err error
	r.reg, err = games.NewRegistry([]games.GameDef{{ID: "g", ContainerName: "g", Status: r.st, Players: r.pl}})
	if err != nil {
		t.Fatal(err)
	}
	r.hub = New(r.reg)
	r.hub.After = r.clk.After
	r.hub.ReconcileInterval = time.Hour
	r.hub.Busy = func(string) bool { return r.busy.Load() }
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel, r.done = cancel, make(chan struct{})
	go func() { r.hub.Run(ctx); close(r.done) }()
	t.Cleanup(r.stop)
	return r
}

func (r *rig) stop() {
	r.cancel()
	<-r.done
}

func TestCadenceFollowsState(t *testing.T) {
	r := newRig(t)
	if tm := r.clk.next(t); tm.d != DefaultIdleInterval {
		t.Fatalf("offline wait = %v, want %v", tm.d, DefaultIdleInterval)
	} else {
		r.st.set(games.StatusOnline)
		tm.c <- time.Time{}
	}
	tm := r.clk.next(t)
	if tm.d != DefaultOnlineInterval {
		t.Fatalf("online wait = %v, want %v", tm.d, DefaultOnlineInterval)
	}
	if o, ok := r.hub.Get("g"); !ok || o.Status != games.StatusOnline || !o.PlayersOK {
		t.Fatalf("Get = %+v %v", o, ok)
	}
	r.busy.Store(true)
	tm.c <- time.Time{}
	if tm := r.clk.next(t); tm.d != DefaultBusyInterval {
		t.Fatalf("busy wait = %v, want %v", tm.d, DefaultBusyInterval)
	}
}

// Players are only asked for when the game could be up.
func TestOfflineSkipsPlayers(t *testing.T) {
	r := newRig(t)
	r.pl.set("ann")
	r.clk.next(t)
	if o, _ := r.hub.Get("g"); o.PlayersOK || o.Count != 0 {
		t.Fatalf("offline observation read players: %+v", o)
	}
}

func TestNotifiesOnlyOnChange(t *testing.T) {
	r := newRig(t)
	sub := r.hub.Subscribe()
	defer sub.Close()
	tm := r.clk.next(t) // first observation is a change
	select {
	case <-sub.C:
	default:
		t.Fatal("no notification for the first observation")
	}

	v := r.hub.Version()
	tm.c <- time.Time{} // same state again
	tm = r.clk.next(t)
	if r.hub.Version() != v {
		t.Fatal("an unchanged observation notified")
	}
	select {
	case <-sub.C:
		t.Fatal("subscriber woken for no change")
	default:
	}

	r.st.set(games.StatusOnline)
	r.pl.set("ann")
	tm.c <- time.Time{}
	tm = r.clk.next(t)
	if r.hub.Version() == v {
		t.Fatal("status change did not notify")
	}
	<-sub.C

	v = r.hub.Version()
	r.pl.set("ann", "bob") // names alone
	tm.c <- time.Time{}
	tm = r.clk.next(t)
	if r.hub.Version() == v {
		t.Fatal("names change did not notify")
	}

	v = r.hub.Version()
	r.busy.Store(true) // Busy flipping alone
	tm.c <- time.Time{}
	r.clk.next(t)
	if r.hub.Version() == v {
		t.Fatal("busy flip did not notify")
	}
}

func TestPokeObservesNowAndCurrentWaitsForIt(t *testing.T) {
	r := newRig(t)
	r.clk.next(t) // first: offline; observer now waits 30s
	d, _ := r.reg.Get("g")
	r.st.set(games.StatusOnline)
	got := make(chan Observation)
	go func() { got <- r.hub.Fresh(context.Background(), d) }()
	if o := <-got; o.Status != games.StatusOnline {
		t.Fatalf("after poke Current = %v, want online", o.Status)
	}
	r.clk.next(t)
	// Pokes coalesce: many at once cost at most two observations.
	r.st.mu.Lock()
	before := r.st.calls
	r.st.mu.Unlock()
	for range 20 {
		r.hub.Poke("g")
	}
	r.clk.next(t)
	select { // a poke landing mid-observation earns one more
	case <-r.clk.timers:
	case <-time.After(30 * time.Millisecond):
	}
	r.clk.none(t)
	r.st.mu.Lock()
	after := r.st.calls
	r.st.mu.Unlock()
	if n := after - before; n < 1 || n > 2 {
		t.Fatalf("20 pokes ran %d observations, want 1 or 2", n)
	}
}

func TestReconcileAddsAndRemovesObservers(t *testing.T) {
	r := newRig(t)
	r.clk.next(t)
	st2 := &fakeStatus{s: games.StatusOnline}
	if err := r.reg.Add(games.GameDef{ID: "h", ContainerName: "h", Status: st2}); err != nil {
		t.Fatal(err)
	}
	r.hub.Poke("h") // unknown id: prompts a reconcile
	if tm := r.clk.next(t); tm.d != DefaultOnlineInterval {
		t.Fatalf("new game's wait = %v", tm.d)
	}
	if o, ok := r.hub.Get("h"); !ok || o.Status != games.StatusOnline {
		t.Fatalf("Get(h) = %+v %v", o, ok)
	}

	sub := r.hub.Subscribe()
	defer sub.Close()
	r.reg.Remove("h")
	r.hub.Reconcile()
	if _, ok := r.hub.Get("h"); ok {
		t.Fatal("removed game still observed")
	}
	select {
	case <-sub.C:
	default:
		t.Fatal("removal did not notify")
	}
	r.hub.mu.Lock()
	n := len(r.hub.games)
	r.hub.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d observers, want 1", n)
	}
}

// A subscriber that never reads must not hold up the observers.
func TestSlowSubscriberDoesNotBlock(t *testing.T) {
	r := newRig(t)
	stuck := r.hub.Subscribe()
	defer stuck.Close()
	tm := r.clk.next(t)
	for i := range 10 {
		if i%2 == 0 {
			r.st.set(games.StatusOnline)
		} else {
			r.st.set(games.StatusOffline)
		}
		tm.c <- time.Time{}
		tm = r.clk.next(t) // would time out if a notification blocked
	}
	if len(stuck.C) != 1 {
		t.Fatalf("pending notifications = %d, want 1 (coalesced)", len(stuck.C))
	}
}

// Without Run there are no observers; Current probes directly.
func TestCurrentWithoutObserverProbes(t *testing.T) {
	st := &fakeStatus{s: games.StatusOnline}
	reg, _ := games.NewRegistry([]games.GameDef{{ID: "g", Status: st}})
	h := New(reg)
	d, _ := reg.Get("g")
	if o := h.Current(context.Background(), d); o.Status != games.StatusOnline {
		t.Fatalf("Current = %+v", o)
	}
	if _, ok := h.Get("g"); ok {
		t.Fatal("a direct probe was stored")
	}
}

func TestStopsOnCancel(t *testing.T) {
	r := newRig(t)
	r.clk.next(t)
	r.stop() // returns only once every observer has exited
	r.hub.mu.Lock()
	defer r.hub.mu.Unlock()
	for id, e := range r.hub.games {
		if !e.exited {
			t.Fatalf("observer %s still running", id)
		}
	}
}
