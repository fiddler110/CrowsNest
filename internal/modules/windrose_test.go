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
