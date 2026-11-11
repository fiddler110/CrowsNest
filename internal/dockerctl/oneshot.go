package dockerctl

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// RunOnce runs a one-shot container to completion and removes it: any old
// container of that name is cleared, spec is created and started, and the
// container is polled (the guard allows no `docker wait`) until it stops or
// timeout passes. A non-zero exit returns an error carrying the last lines of
// its output. poll is the polling interval (default 1 second).
func (c *Client) RunOnce(ctx context.Context, spec CreateSpec, timeout, poll time.Duration) error {
	if poll <= 0 {
		poll = time.Second
	}
	remove := func() {
		rctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = c.Remove(rctx, spec.Name)
	}
	if ok, err := c.Exists(ctx, spec.Name); err != nil {
		return err
	} else if ok {
		if err := c.Remove(ctx, spec.Name); err != nil {
			return fmt.Errorf("clearing an old %s container: %w", spec.Name, err)
		}
	}
	if err := c.Create(ctx, spec); err != nil {
		return fmt.Errorf("creating %s: %w", spec.Name, err)
	}
	defer remove()
	if err := c.Start(ctx, Target{ContainerName: spec.Name}); err != nil {
		return fmt.Errorf("starting %s: %w", spec.Name, err)
	}
	deadline := time.Now().Add(timeout)
	for {
		st, err := c.State(ctx, spec.Name)
		if err != nil {
			return err
		}
		if !st.Running && !st.FinishedAt.IsZero() {
			if st.ExitCode == 0 {
				return nil
			}
			out := "(no output)"
			if rc, err := c.Logs(ctx, spec.Name, "", "20"); err == nil {
				b, _ := io.ReadAll(io.LimitReader(rc, 4096))
				_ = rc.Close()
				out = strings.TrimSpace(string(b))
			}
			return fmt.Errorf("%s exited with status %d: %s", spec.Name, st.ExitCode, out)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not finish within %s", spec.Name, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}
