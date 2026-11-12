package playerwatch

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/statehub"
)

type status struct{ s games.Status }

func (f *status) Check(context.Context, string) (games.Status, error) { return f.s, nil }

type players struct {
	count int
	names []string
	ok    bool
}

func (p *players) PlayerCount(context.Context) (int, []string, bool) { return p.count, p.names, p.ok }

type sink struct{ msgs []string }

func (s *sink) Notify(_ context.Context, m string) { s.msgs = append(s.msgs, m) }

func setup(t *testing.T) (*Watcher, *status, *players, *sink) {
	t.Helper()
	st, pl, out := &status{games.StatusOnline}, &players{ok: true}, &sink{}
	reg, err := games.NewRegistry([]games.GameDef{{ID: "g", DisplayName: "Game", ContainerName: "g", Status: st, Players: pl}})
	if err != nil {
		t.Fatal(err)
	}
	return New(reg, out, 0), st, pl, out
}

func TestJoinLeaveByName(t *testing.T) {
	w, _, pl, out := setup(t)
	ctx := context.Background()

	pl.names = []string{"ann"}
	w.Tick(ctx) // baseline: ann was already there
	if len(out.msgs) != 0 {
		t.Fatalf("baseline announced %v", out.msgs)
	}
	pl.names = []string{"ann", "bob"}
	w.Tick(ctx)
	pl.names = []string{"bob"}
	w.Tick(ctx)
	if len(out.msgs) != 2 || !strings.Contains(out.msgs[0], "bob") || !strings.Contains(out.msgs[0], "joined") ||
		!strings.Contains(out.msgs[1], "ann") || !strings.Contains(out.msgs[1], "left") {
		t.Fatalf("messages = %v", out.msgs)
	}
}

func TestCountOnlyAndUnreadable(t *testing.T) {
	w, st, pl, out := setup(t)
	ctx := context.Background()

	pl.count = 1
	w.Tick(ctx)
	pl.ok = false
	w.Tick(ctx) // unreadable: silent, baseline kept
	pl.ok, pl.count = true, 2
	w.Tick(ctx)
	if len(out.msgs) != 1 || !strings.Contains(out.msgs[0], "Someone joined") {
		t.Fatalf("messages = %v", out.msgs)
	}

	// Going offline resets the baseline, so the next run doesn't announce its first reading.
	st.s = games.StatusOffline
	w.Tick(ctx)
	st.s, pl.count = games.StatusOnline, 5
	w.Tick(ctx)
	if len(out.msgs) != 1 {
		t.Fatalf("a fresh run announced %v", out.msgs)
	}
}

type rec struct{ events []string }

func (r *rec) Record(kind, game, actor, detail string) {
	r.events = append(r.events, kind+":"+game+":"+actor)
}

// A game confirmed offline closes out everyone still listed, so playtime
// doesn't rely on a stop event alone.
func TestOfflineRecordsLeaves(t *testing.T) {
	w, st, pl, out := setup(t)
	h := &rec{}
	w.History = h
	ctx := context.Background()

	pl.names = []string{"ann", "bob"}
	w.Tick(ctx) // baseline
	st.s = games.StatusOffline
	w.Tick(ctx)
	if len(h.events) != 2 || h.events[0] != "leave:g:ann" || h.events[1] != "leave:g:bob" {
		t.Fatalf("events = %v, want leaves for ann and bob", h.events)
	}
	if len(out.msgs) != 0 {
		t.Fatalf("offline announced %v", out.msgs)
	}
	w.Tick(ctx)
	if len(h.events) != 2 {
		t.Fatalf("leaves recorded twice: %v", h.events)
	}
}

// The last player leaving a game that reports names comes back as an empty
// list, not a count-only reading: the leave must still be recorded by name
// (found live on Palworld, where the final leave was announced as "Someone
// left" and never closed the player's playtime).
func TestLastNamedPlayerLeaves(t *testing.T) {
	w, _, pl, out := setup(t)
	h := &rec{}
	w.History = h
	ctx := context.Background()

	pl.names = []string{"ann"}
	w.Tick(ctx) // baseline
	pl.names, pl.count = nil, 0
	w.Tick(ctx)
	if len(h.events) != 1 || h.events[0] != "leave:g:ann" {
		t.Fatalf("events = %v, want leave for ann", h.events)
	}
	if len(out.msgs) != 1 || !strings.Contains(out.msgs[0], "ann") || strings.Contains(out.msgs[0], "Someone") {
		t.Fatalf("messages = %v, want a named leave", out.msgs)
	}
	w.Tick(ctx)
	if len(h.events) != 1 {
		t.Fatalf("leave recorded twice: %v", h.events)
	}
}

type hubStatus struct {
	mu  sync.Mutex
	s   games.Status
	err error
}

func (f *hubStatus) set(s games.Status, err error) { f.mu.Lock(); f.s, f.err = s, err; f.mu.Unlock() }
func (f *hubStatus) Check(context.Context, string) (games.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.s, f.err
}

type hubPlayers struct {
	mu    sync.Mutex
	names []string
}

func (p *hubPlayers) set(n ...string) { p.mu.Lock(); p.names = n; p.mu.Unlock() }
func (p *hubPlayers) PlayerCount(context.Context) (int, []string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.names), p.names, true
}

// Driven by the state hub: joins are announced, an unreadable status keeps
// the baseline (no leaves), and only a confirmed offline closes everyone out.
func TestHubDriven_LeavesOnlyWhenConfirmedOffline(t *testing.T) {
	st, pl := &hubStatus{s: games.StatusOnline}, &hubPlayers{}
	reg, err := games.NewRegistry([]games.GameDef{{ID: "g", DisplayName: "Game", ContainerName: "g", Status: st, Players: pl}})
	if err != nil {
		t.Fatal(err)
	}
	hub := statehub.New(reg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { hub.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	out, h := &sink{}, &rec{}
	w := New(reg, out, 0)
	w.Hub = hub
	d, _ := reg.Get("g")
	step := func() { hub.Fresh(ctx, d); w.Tick(ctx) }

	pl.set("ann")
	for { // wait for the hub's observer to come up
		if _, ok := hub.Get("g"); ok {
			break
		}
		time.Sleep(time.Millisecond)
	}
	step() // baseline
	w.History = h
	pl.set("ann", "bob")
	step()
	if len(out.msgs) != 1 || !strings.Contains(out.msgs[0], "bob") {
		t.Fatalf("messages = %v", out.msgs)
	}

	st.set(games.StatusOffline, errors.New("docker unreachable"))
	step()
	if len(h.events) != 1 { // just bob's join
		t.Fatalf("an unreadable status recorded leaves: %v", h.events)
	}

	st.set(games.StatusOffline, nil)
	step()
	if len(h.events) != 3 || h.events[1] != "leave:g:ann" || h.events[2] != "leave:g:bob" {
		t.Fatalf("events = %v, want bob's join then leaves for ann and bob", h.events)
	}
}
