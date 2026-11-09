package modules

import (
	"context"
	"os"
	"strings"
	"testing"
)

// testdata/minecraft_session.log is representative itzg/minecraft-server output
// (vanilla server log format) with two players, plus a chat line that spells
// out "joined the game" and must not count.
func TestMinecraftSession(t *testing.T) {
	b, err := os.ReadFile("testdata/minecraft_session.log")
	if err != nil {
		t.Fatal(err)
	}
	tr := trackerFor(t, "minecraft")
	var peak int
	var afterSteveLeft = -1
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		tr.Replay(strings.NewReader(l))
		n, _, _ := tr.PlayerCount(context.Background())
		if n > peak {
			peak = n
		}
		if strings.Contains(l, "Steve left the game") {
			afterSteveLeft = n
		}
	}
	if !tr.Ready() {
		t.Error("the Done line did not latch ready")
	}
	if peak != 2 {
		t.Errorf("peak = %d, want 2 (the chat line must not count)", peak)
	}
	if afterSteveLeft != 0 {
		t.Errorf("count after both left = %d, want 0", afterSteveLeft)
	}
}

func TestMinecraftNotReadyBeforeDone(t *testing.T) {
	tr := trackerFor(t, "minecraft")
	tr.Replay(strings.NewReader("[17:02:19] [Server thread/INFO]: Preparing spawn area: 97%\n"))
	if tr.Ready() {
		t.Fatal("ready before the Done line")
	}
}
