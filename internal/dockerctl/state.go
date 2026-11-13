package dockerctl

import (
	"context"
	"fmt"
	"time"
)

// ContainerState is what a crash watcher needs from one inspect: whether the
// container is up, how its last run ended and how often docker has restarted it.
type ContainerState struct {
	Running      bool
	ExitCode     int // of the last finished run; kept while the container runs again
	OOMKilled    bool
	FinishedAt   time.Time // zero when it has never stopped
	RestartCount int
}

// State reads the container's current ContainerState. A container that does
// not exist is an error (use Exists first when that is a normal case).
func (c *Client) State(ctx context.Context, name string) (ContainerState, error) {
	ctx, cancel := c.opCtx(ctx, defaultShortTimeout)
	defer cancel()
	ir, err := c.inspect(ctx, name)
	if err != nil {
		return ContainerState{}, err
	}
	fin, err := parseFinished(ir.State.FinishedAt)
	if err != nil {
		return ContainerState{}, err
	}
	return ContainerState{Running: ir.State.Running, ExitCode: ir.State.ExitCode,
		OOMKilled: ir.State.OOMKilled, FinishedAt: fin, RestartCount: ir.RestartCount}, nil
}

func parseFinished(ts string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, fmt.Errorf("dockerctl: parse FinishedAt %q: %w", ts, err)
	}
	if t.Year() <= 1 {
		return time.Time{}, nil // docker reports 0001-01-01 for "never"
	}
	return t, nil
}
