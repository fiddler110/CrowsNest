// Package windrose provides Windrose's container-status detection. The
// server prints a ready marker to its stdout, so a log-following Tracker
// (internal/logtrack) distinguishes "starting" from "online"
// without any `docker exec`.
package windrose

import (
	"regexp"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/logtrack"
)

// ReadyMarker is the log line (on the container's stdout) that marks the
// server as ready for players.
const ReadyMarker = "Host server is ready for owner to connect"

// NewTracker builds the log-following status tracker for the named
// container (starting vs. online); the caller starts its Run once.
func NewTracker(docker *dockerctl.Client, containerName string) *logtrack.Tracker {
	return logtrack.New(docker, containerName, logtrack.Spec{
		Name:  "windrose",
		Ready: regexp.MustCompile(regexp.QuoteMeta(ReadyMarker)),
	})
}

// Startup is Windrose's startup-progress matcher: a single milestone.
var Startup = &games.StartupMatcher{
	Milestones: []games.Milestone{
		{Pattern: regexp.MustCompile(regexp.QuoteMeta(ReadyMarker)), Pct: 100, Label: "Host server ready"},
	},
}
