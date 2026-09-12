// Package windrose provides Windrose's real container-status detection,
// ported directly from the original Python CrowsNest (see app.py's
// _get_container_status_uncached): a single log-marker grep distinguishes
// "starting" from "online" once the container itself is running.
package windrose

import (
	"context"
	"errors"
	"os/exec"
	"regexp"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

const (
	// LogPath is where the Unreal Engine server writes its current-session
	// log inside the container. UE rotates R5.log to a timestamped backup
	// on each boot, so this file only ever contains the current session's
	// output — no stale-marker risk across restarts.
	LogPath = "/home/steam/server-files/R5/Saved/Logs/R5.log"

	// ReadyMarker is the exact log line the original Python CrowsNest greps
	// for to distinguish "starting" from "online".
	ReadyMarker = "Host server is ready for owner to connect"
)

// StatusChecker implements games.StatusChecker for Windrose.
type StatusChecker struct {
	Docker *dockerctl.Client
}

func (c *StatusChecker) Check(ctx context.Context, containerName string) (games.Status, error) {
	running, err := c.Docker.Running(ctx, containerName)
	if err != nil {
		return games.StatusUnknown, err
	}
	if !running {
		return games.StatusOffline, nil
	}

	_, err = c.Docker.Exec(ctx, containerName, "grep", "-q", ReadyMarker, LogPath)
	if err == nil {
		return games.StatusOnline, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return games.StatusStarting, nil
	}
	return games.StatusUnknown, err
}

// Startup is Windrose's startup-progress matcher. This is deliberately a
// single milestone, not a multi-step table — the original Python CrowsNest
// never tracked more than this one marker.
var Startup = &games.StartupMatcher{
	Milestones: []games.Milestone{
		{Pattern: regexp.MustCompile(regexp.QuoteMeta(ReadyMarker)), Pct: 100, Label: "Host server ready"},
	},
}
