package games

import (
	"context"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
)

// DockerStatusChecker reports StatusOnline/StatusOffline from `docker ps`
// alone, with no game-aware "starting" detection. It's the Phase 3 baseline
// every configured game gets by default; per-game packages (Phase 10)
// replace it with log-marker-aware checkers where a game needs the
// distinction.
type DockerStatusChecker struct {
	Docker *dockerctl.Client
}

func (c *DockerStatusChecker) Check(ctx context.Context, containerName string) (Status, error) {
	running, err := c.Docker.Running(ctx, containerName)
	if err != nil {
		return StatusUnknown, err
	}
	if running {
		return StatusOnline, nil
	}
	return StatusOffline, nil
}

// UnknownPlayerCounter is the Phase 3 baseline PlayerCounter for games that
// don't have a real integration wired yet. It always reports ok=false so
// idle auto-stop treats the count as undeterminable rather than assuming
// zero players and shutting down a game it can't actually see into.
type UnknownPlayerCounter struct{}

func (UnknownPlayerCounter) PlayerCount(ctx context.Context) (count int, names []string, ok bool) {
	return 0, nil, false
}
