package playerwatch

import (
	"context"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/games"
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
