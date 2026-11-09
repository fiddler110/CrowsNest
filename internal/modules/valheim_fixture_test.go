package modules

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/logtrack"
)

// testdata/valheim_session.log is a real lloesche/valheim-server session
// (2026-11-07): one player joins, then leaves, then rejoins. Steam ID and
// character name are anonymised. This is the first verification of the
// Valheim join/leave markers against a real player.
func TestValheimRealSession(t *testing.T) {
	b, err := os.ReadFile("testdata/valheim_session.log")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(b), "\n")
	tr := valheimTracker(t)
	count := func() int { n, _, _ := tr.PlayerCount(context.Background()); return n }
	var peak, after int
	for _, l := range lines {
		tr.Replay(strings.NewReader(l))
		if c := count(); c > peak {
			peak = c
		}
		after = count()
	}
	if peak != 1 {
		t.Errorf("peak players = %d, want 1", peak)
	}
	if after != 0 { // both sessions end with a leave
		t.Errorf("players at end of fixture = %d, want 0", after)
	}
	// Up to just after the first "Closing socket" the count returns to 0.
	tr2 := valheimTracker(t)
	for _, l := range lines {
		tr2.Replay(strings.NewReader(l))
		if strings.Contains(l, "Closing socket") {
			break
		}
	}
	if n, _, _ := tr2.PlayerCount(context.Background()); n != 0 {
		t.Errorf("after first leave = %d, want 0", n)
	}
}

// Real ready lines from the same run: the early "Loading: Done, Total time"
// must NOT latch ready (the world is not loaded yet); the later
// "Loading: Done. Total seconds sinze ZNet start" must.
func TestValheimRealReadyLines(t *testing.T) {
	tr := valheimTracker(t)
	tr.Replay(strings.NewReader("Nov  7 19:37:04 supervisord: valheim-server 11/07/2026 19:37:04: Loading: Done, Total time: -7.810839\n"))
	if tr.Ready() {
		t.Fatal("early 'Loading: Done,' line latched ready")
	}
	tr.Replay(strings.NewReader("Nov  7 19:38:55 supervisord: valheim-server 11/07/2026 19:38:55: Loading: Done. Total seconds sinze ZNet start: 37.604965\n"))
	if !tr.Ready() {
		t.Fatal("real ready line did not latch")
	}
}

// valheimTracker wires the embedded valheim module and returns its log tracker.
func valheimTracker(t *testing.T) *logtrack.Tracker {
	t.Helper()
	var def games.GameDef
	runners := Bundled().wire["valheim"](&def, Env{})
	if len(runners) != 1 {
		t.Fatalf("runners = %d, want 1", len(runners))
	}
	return runners[0].(*logtrack.Tracker)
}
