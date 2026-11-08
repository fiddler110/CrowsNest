package windrose

import (
	"strings"
	"testing"
)

const readyLine = "[2026.09.11-20.15.33:123][456]LogGameSession: Host server is ready for owner to connect"

func TestScan_LatchesReady(t *testing.T) {
	tr := NewTracker(nil, "windrose")
	tr.scan(strings.NewReader("booting\n" + readyLine + "\nmore output\n"))
	if !tr.ready {
		t.Fatal("ready not latched after marker line")
	}
}

func TestScan_UnrelatedLinesDoNotFlip(t *testing.T) {
	tr := NewTracker(nil, "windrose")
	tr.scan(strings.NewReader("LogGameSession: Waiting for players to join\nHost server is starting\n"))
	if tr.ready {
		t.Fatal("ready flipped by unrelated lines")
	}
}

func TestReset_ClearsReady(t *testing.T) {
	tr := NewTracker(nil, "windrose")
	tr.scan(strings.NewReader(readyLine + "\n"))
	tr.reset()
	if tr.ready {
		t.Fatal("reset did not clear ready")
	}
}

func TestStartupMilestone_MatchesReadyLine(t *testing.T) {
	line := "[2026.09.11-20.15.33:123][456]LogGameSession: Host server is ready for owner to connect"
	if !Startup.Milestones[0].Pattern.MatchString(line) {
		t.Fatalf("pattern %q did not match ready line %q", Startup.Milestones[0].Pattern, line)
	}
}

func TestStartupMilestone_DoesNotMatchUnrelatedLine(t *testing.T) {
	line := "[2026.09.11-20.14.02:001][002]LogGameSession: Waiting for players to join"
	if Startup.Milestones[0].Pattern.MatchString(line) {
		t.Fatalf("pattern %q unexpectedly matched unrelated line %q", Startup.Milestones[0].Pattern, line)
	}
}
