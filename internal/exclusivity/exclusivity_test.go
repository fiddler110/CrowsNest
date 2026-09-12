package exclusivity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

// newRegistry builds a registry of docker-ps-status-checked GameDefs, one
// per id.
func newRegistry(t *testing.T, docker *dockerctl.Client, ids ...string) *games.Registry {
	t.Helper()
	defs := make([]games.GameDef, len(ids))
	for i, id := range ids {
		defs[i] = games.GameDef{
			ID:            id,
			DisplayName:   id,
			ContainerName: id,
			Status:        &games.DockerStatusChecker{Docker: docker},
			Players:       games.UnknownPlayerCounter{},
		}
	}
	r, err := games.NewRegistry(defs)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	return r
}

// newStaticFakeDocker builds a docker replacement whose `ps -a`/`ps`
// answers are fixed for the whole test (existing vs. running containers),
// unaffected by start/stop calls. Good for scenarios that don't need a
// stop to actually change what a later status check reports.
func newStaticFakeDocker(t *testing.T, existing, running []string) *dockerctl.Client {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "docker")
	script := `#!/bin/sh
case "$1" in
  start) exit 0 ;;
  stop) exit 0 ;;
  ps)
    if [ "$2" = "-a" ]; then
      candidates="$EXISTING"
    else
      candidates="$RUNNING"
    fi
    for n in $candidates; do
      case "$*" in *"name=^$n\$"*) echo "$n"; break ;; esac
    done
    ;;
esac
`
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	t.Setenv("EXISTING", strings.Join(existing, " "))
	t.Setenv("RUNNING", strings.Join(running, " "))
	return &dockerctl.Client{DockerBin: binPath}
}

// newStatefulFakeDocker builds a docker replacement that tracks running
// containers in a state file: `start`/`stop` actually mutate it, so a
// later status check reflects prior calls. existing lists containers
// start can bring up via `docker start` (vs. needing compose, which these
// tests don't exercise); runningInitially seeds the state file.
func newStatefulFakeDocker(t *testing.T, existing, runningInitially []string) *dockerctl.Client {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "docker")
	statePath := filepath.Join(dir, "state")
	if err := os.WriteFile(statePath, []byte(strings.Join(runningInitially, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	script := `#!/bin/sh
case "$1" in
  start)
    name="$2"
    grep -qx "$name" "$FAKE_DOCKER_STATE" 2>/dev/null || echo "$name" >> "$FAKE_DOCKER_STATE"
    exit 0
    ;;
  stop)
    name="$2"
    grep -vx "$name" "$FAKE_DOCKER_STATE" > "$FAKE_DOCKER_STATE.tmp" 2>/dev/null
    mv "$FAKE_DOCKER_STATE.tmp" "$FAKE_DOCKER_STATE"
    exit 0
    ;;
  ps)
    if [ "$2" = "-a" ]; then
      candidates="$EXISTING $(cat "$FAKE_DOCKER_STATE" 2>/dev/null)"
    else
      candidates="$(cat "$FAKE_DOCKER_STATE" 2>/dev/null)"
    fi
    for n in $candidates; do
      case "$*" in *"name=^$n\$"*) echo "$n"; break ;; esac
    done
    ;;
esac
`
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	t.Setenv("FAKE_DOCKER_STATE", statePath)
	t.Setenv("EXISTING", strings.Join(existing, " "))
	return &dockerctl.Client{DockerBin: binPath}
}

func TestActiveGame_None(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, nil)
	registry := newRegistry(t, docker, "windrose", "valheim")
	mgr := NewManager(registry, docker)

	if _, ok := mgr.ActiveGame(context.Background()); ok {
		t.Fatal("ActiveGame() ok = true, want false when nothing is running")
	}
}

func TestActiveGame_Found(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, []string{"valheim"})
	registry := newRegistry(t, docker, "windrose", "valheim", "palworld")
	mgr := NewManager(registry, docker)

	active, ok := mgr.ActiveGame(context.Background())
	if !ok || active != "valheim" {
		t.Fatalf("ActiveGame() = (%q, %v), want (valheim, true)", active, ok)
	}
}

func TestRequestStart_NoConflict(t *testing.T) {
	docker := newStaticFakeDocker(t, []string{"windrose"}, nil)
	registry := newRegistry(t, docker, "windrose")
	mgr := NewManager(registry, docker)

	if err := mgr.RequestStart(context.Background(), "windrose"); err != nil {
		t.Fatalf("RequestStart() error = %v", err)
	}
}

func TestRequestStart_Conflict(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, []string{"valheim"})
	registry := newRegistry(t, docker, "valheim", "palworld")
	mgr := NewManager(registry, docker)

	err := mgr.RequestStart(context.Background(), "palworld")
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("RequestStart() error = %v, want *ConflictError", err)
	}
	if conflict.Active != "valheim" {
		t.Fatalf("ConflictError.Active = %q, want valheim", conflict.Active)
	}
}

func TestRequestStart_AlreadyActiveIsNotAConflict(t *testing.T) {
	docker := newStaticFakeDocker(t, []string{"windrose"}, []string{"windrose"})
	registry := newRegistry(t, docker, "windrose")
	mgr := NewManager(registry, docker)

	if err := mgr.RequestStart(context.Background(), "windrose"); err != nil {
		t.Fatalf("RequestStart() error = %v, want nil (restarting the already-active game is not a conflict)", err)
	}
}

func TestRequestStart_UnknownGame(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, nil)
	registry := newRegistry(t, docker)
	mgr := NewManager(registry, docker)

	if err := mgr.RequestStart(context.Background(), "ghost"); err == nil {
		t.Fatal("RequestStart() error = nil, want error for an unregistered game")
	}
}

func TestStop(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, []string{"windrose"})
	registry := newRegistry(t, docker, "windrose")
	mgr := NewManager(registry, docker)

	if err := mgr.Stop(context.Background(), "windrose"); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestConfirmSwitch(t *testing.T) {
	docker := newStatefulFakeDocker(t, []string{"palworld"}, []string{"valheim"})
	registry := newRegistry(t, docker, "windrose", "valheim", "palworld")
	mgr := NewManager(registry, docker)
	mgr.StopPollInterval = time.Millisecond
	mgr.StopPollTimeout = time.Second

	if err := mgr.ConfirmSwitch(context.Background(), "valheim", "palworld"); err != nil {
		t.Fatalf("ConfirmSwitch() error = %v", err)
	}

	active, ok := mgr.ActiveGame(context.Background())
	if !ok || active != "palworld" {
		t.Fatalf("ActiveGame() after switch = (%q, %v), want (palworld, true)", active, ok)
	}
}

func TestConfirmSwitch_TimesOutIfNeverStops(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, []string{"stuck-game"})
	registry := newRegistry(t, docker, "stuck-game", "other")
	mgr := NewManager(registry, docker)
	mgr.StopPollInterval = time.Millisecond
	mgr.StopPollTimeout = 20 * time.Millisecond

	err := mgr.ConfirmSwitch(context.Background(), "stuck-game", "other")
	if err == nil {
		t.Fatal("ConfirmSwitch() error = nil, want a timeout error when the source game never reports offline")
	}
}

func TestConfirmSwitch_UnknownSource(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, nil)
	registry := newRegistry(t, docker, "other")
	mgr := NewManager(registry, docker)

	if err := mgr.ConfirmSwitch(context.Background(), "ghost", "other"); err == nil {
		t.Fatal("ConfirmSwitch() error = nil, want error for an unregistered source game")
	}
}
