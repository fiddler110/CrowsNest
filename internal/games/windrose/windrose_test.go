package windrose

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

// newFakeDocker writes script as an executable "docker" replacement and
// returns a Client pointed at it, following the fake-docker-script idiom
// used throughout this repo (see internal/exclusivity/exclusivity_test.go).
func newFakeDocker(t *testing.T, script string) *dockerctl.Client {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "docker")
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	return &dockerctl.Client{DockerBin: binPath}
}

func TestCheck_NotRunning(t *testing.T) {
	docker := newFakeDocker(t, `#!/bin/sh
case "$1" in
  ps) : ;;
  exec) exit 1 ;;
esac
`)
	checker := &StatusChecker{Docker: docker}

	status, err := checker.Check(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if status != games.StatusOffline {
		t.Fatalf("Check() = %v, want %v", status, games.StatusOffline)
	}
}

func TestCheck_RunningAndReady(t *testing.T) {
	docker := newFakeDocker(t, `#!/bin/sh
case "$1" in
  ps) echo "windrose" ;;
  exec) exit 0 ;;
esac
`)
	checker := &StatusChecker{Docker: docker}

	status, err := checker.Check(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if status != games.StatusOnline {
		t.Fatalf("Check() = %v, want %v", status, games.StatusOnline)
	}
}

func TestCheck_RunningMarkerNotFound(t *testing.T) {
	docker := newFakeDocker(t, `#!/bin/sh
case "$1" in
  ps) echo "windrose" ;;
  exec) exit 1 ;;
esac
`)
	checker := &StatusChecker{Docker: docker}

	status, err := checker.Check(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if status != games.StatusStarting {
		t.Fatalf("Check() = %v, want %v", status, games.StatusStarting)
	}
}

func TestCheck_RunningLogFileMissing(t *testing.T) {
	docker := newFakeDocker(t, `#!/bin/sh
case "$1" in
  ps) echo "windrose" ;;
  exec) exit 2 ;;
esac
`)
	checker := &StatusChecker{Docker: docker}

	status, err := checker.Check(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if status != games.StatusStarting {
		t.Fatalf("Check() = %v, want %v", status, games.StatusStarting)
	}
}

func TestCheck_ExecTimeout(t *testing.T) {
	docker := newFakeDocker(t, `#!/bin/sh
case "$1" in
  ps) echo "windrose" ;;
  exec) sleep 2 ;;
esac
`)
	docker.Timeout = 20 * time.Millisecond
	checker := &StatusChecker{Docker: docker}

	status, err := checker.Check(context.Background(), "windrose")
	if err == nil {
		t.Fatal("Check() error = nil, want error on exec timeout")
	}
	if status != games.StatusUnknown {
		t.Fatalf("Check() = %v, want %v", status, games.StatusUnknown)
	}
}

func TestCheck_PsFails(t *testing.T) {
	docker := newFakeDocker(t, `#!/bin/sh
case "$1" in
  ps) exit 1 ;;
  exec) exit 0 ;;
esac
`)
	checker := &StatusChecker{Docker: docker}

	status, err := checker.Check(context.Background(), "windrose")
	if err == nil {
		t.Fatal("Check() error = nil, want error when `docker ps` fails")
	}
	if status != games.StatusUnknown {
		t.Fatalf("Check() = %v, want %v", status, games.StatusUnknown)
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
