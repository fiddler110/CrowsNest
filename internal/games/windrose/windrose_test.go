package windrose

import "testing"

const readyLine = "[2026.09.11-20.15.33:123][456]LogGameSession: Host server is ready for owner to connect"

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
