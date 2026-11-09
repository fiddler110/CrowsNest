package modules

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/games"
)

// testdata/windrose_session.log is the join-related and leave-related lines
// of a real Windrose session (2026-11-08): connect, handshake, play, then the
// client dropped (ConnectionTimeout). Ids and names are anonymised.
func TestWindroseRealSession(t *testing.T) {
	b, err := os.ReadFile("testdata/windrose_session.log")
	if err != nil {
		t.Fatal(err)
	}
	tr := trackerFor(t, "windrose")
	counts := map[string]int{}
	var order []string
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		tr.Replay(strings.NewReader(l))
		n, _, _ := tr.PlayerCount(context.Background())
		key := strings.TrimSpace(l)
		counts[key] = n
		order = append(order, key)
	}
	at := func(sub string) int {
		for _, k := range order {
			if strings.Contains(k, sub) {
				return counts[k]
			}
		}
		t.Fatalf("no fixture line containing %q", sub)
		return -1
	}
	if !tr.Ready() {
		t.Error("the ready marker was not recognised")
	}
	// The P2P "Add player" lines come before a connection exists: not a join.
	if got := at("OnAddPlayer"); got != 0 {
		t.Errorf("count after P2P Add player = %d, want 0", got)
	}
	if got := at("Login request"); got != 1 {
		t.Errorf("count after Login request = %d, want 1", got)
	}
	// The handshake's TCP Disconnect 9 s after the join must not look like a leave.
	if got := at("(TCP)"); got != 0 { // it precedes the login in the file
		t.Errorf("count at TCP Disconnect = %d, want 0 (before login)", got)
	}
	if got := at("Join request"); got != 1 {
		t.Errorf("count after lobby Join request (same session) = %d, want 1", got)
	}
	if got := at("RemoveClientConnection"); got != 0 {
		t.Errorf("count after RemoveClientConnection = %d, want 0", got)
	}
}

type fixedCounter struct {
	n  int
	ok bool
}

func (f fixedCounter) PlayerCount(context.Context) (int, []string, bool) { return f.n, nil, f.ok }

func TestWindroseExtension(t *testing.T) {
	// No Windrose+ URL: nothing is added on top of the manifest.
	def := &games.GameDef{ID: "windrose", ContainerName: "windrose"}
	Bundled().wire["windrose"](def, Env{})
	if _, isTracker := def.Info.(interface{ Ready() bool }); !isTracker || any(def.Info) != any(def.Players) {
		t.Errorf("without http_api_url info and players must both be the log tracker, got %T / %T", def.Info, def.Players)
	}

	// With it, the Windrose+ client feeds the info panel and the log decides the count.
	def = &games.GameDef{ID: "windrose", ContainerName: "windrose"}
	Bundled().wire["windrose"](def, Env{Config: config.GameConfig{Options: map[string]string{"http_api_url": "http://x:8780"}}})
	if _, ok := def.Players.(*comparingCounter); !ok {
		t.Fatalf("players = %T, want the comparing counter", def.Players)
	}
	if def.Console == nil || def.RawConsole == nil {
		t.Error("Windrose+ must provide the admin console and the raw console")
	}
	if _, ok := def.Status.(interface{ Ready() bool }); !ok {
		t.Errorf("status = %T, must stay the log tracker", def.Status)
	}
}

func TestComparingCounterReturnsPrimary(t *testing.T) {
	c := &comparingCounter{name: "t", primary: fixedCounter{2, true}, other: fixedCounter{3, true}}
	if n, _, ok := c.PlayerCount(context.Background()); !ok || n != 2 {
		t.Errorf("primary must win: %d %v", n, ok)
	}
	c = &comparingCounter{name: "t", primary: fixedCounter{0, false}, other: fixedCounter{3, true}}
	if _, _, ok := c.PlayerCount(context.Background()); ok {
		t.Error("an unknown primary must stay unknown, not fall back to the other source")
	}
	c = &comparingCounter{name: "t", primary: fixedCounter{1, true}}
	if n, _, ok := c.PlayerCount(context.Background()); !ok || n != 1 {
		t.Errorf("no other source: %d %v", n, ok)
	}
}

// ids in, names out: the names must not flap between ids and real names, or the
// join/leave notices (which diff names between polls) would announce phantoms.
func TestComparingCounterNamesAreStable(t *testing.T) {
	log := &scriptedCounter{}
	mod := &scriptedCounter{}
	c := &comparingCounter{name: "t", primary: log, other: mod, namesFromOther: true}
	poll := func() (int, []string) {
		n, names, _ := c.PlayerCount(context.Background())
		return n, names
	}

	log.set(1, "id-a")
	mod.set(1, "Ann")
	if n, names := poll(); n != 1 || len(names) != 1 || names[0] != "Ann" {
		t.Fatalf("agreed: %d %v, want 1 [Ann]", n, names)
	}
	// Windrose+ drops out: same player, so the agreed name is kept.
	mod.down()
	if n, names := poll(); n != 1 || len(names) != 1 || names[0] != "Ann" {
		t.Fatalf("mod down, unchanged players: %d %v, want 1 [Ann]", n, names)
	}
	// A second player joins while the mod lags: count only, never a raw id.
	log.set(2, "id-a", "id-b")
	mod.set(1, "Ann")
	if n, names := poll(); n != 2 || names != nil {
		t.Fatalf("mod lagging: %d %v, want 2 and no names", n, names)
	}
	// The mod catches up.
	mod.set(2, "Ann", "Bob")
	if n, names := poll(); n != 2 || len(names) != 2 {
		t.Fatalf("caught up: %d %v", n, names)
	}
	// Everyone leaves, then someone new joins with the mod down: no stale names.
	log.set(0)
	mod.down()
	poll()
	log.set(1, "id-c")
	if n, names := poll(); n != 1 || names != nil {
		t.Fatalf("new player, mod down: %d %v, want 1 and no names", n, names)
	}
}

type scriptedCounter struct {
	n     int
	names []string
	ok    bool
}

func (s *scriptedCounter) set(n int, names ...string) { s.n, s.names, s.ok = n, names, true }
func (s *scriptedCounter) down()                      { s.n, s.names, s.ok = 0, nil, false }
func (s *scriptedCounter) PlayerCount(context.Context) (int, []string, bool) {
	return s.n, s.names, s.ok
}
