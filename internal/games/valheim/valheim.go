// Package valheim implements Valheim's player tracking by tailing the
// dedicated server's own log output — it has no first-party status/query
// API. Join/leave detection is based on two log lines documented by the
// community around the lloesche/valheim-server-docker image (see
// docs/implementation-plan.md phase 10):
//
//	"Got handshake from client <steamid>"  — a client begins connecting
//	"Closing socket <steamid>"             — a client's connection closes
//
// The join/leave markers have NOT been verified with a real player connecting
// (the plan's "⚠️ spike" for this game); the regexes are deliberately
// permissive (matching everything after the marker phrase, not just digits)
// since newer Valheim versions are reported to prefix the id with "V_". Treat
// the count as best-effort. The readiness marker and startup milestones, by
// contrast, were read from a real lloesche/valheim-server container
// (2026-09-30, Valheim l-1.0.16): the same log tail also tells us when the
// world has finished loading, which docker-ps alone cannot.
package valheim

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/logtrack"
)

var (
	connectRe    = regexp.MustCompile(`Got handshake from client (\S+)`)
	disconnectRe = regexp.MustCompile(`Closing socket (\S+)`)

	// readyRe marks the world loaded and the server open for joins:
	//   "Loading: Done. Total seconds sinze ZNet start: ..."  (sic)
	//   "Opened Steam server"
	// worldRe captures the world name from the "Load world: <name>" line the
	// startup milestone already keys on (the name's exact format is
	// unverified, so it is only shown, never relied on).
	worldRe = regexp.MustCompile(`Load world:\s*(.+?)\s*$`)

	readyRe = regexp.MustCompile(`Loading: Done\.|Opened Steam server`)
)

// Startup drives Valheim's progress bar from the container's log. First boot
// spends its time in SteamCMD (same "Update state (0x61) downloading" lines
// as Palworld), mapped onto 10-70% by Parse; later milestones cover world
// load.
var Startup = &games.StartupMatcher{
	Milestones: []games.Milestone{
		{Pattern: regexp.MustCompile(`Downloading/updating/validating Valheim server`), Pct: 5, Label: "Checking for updates"},
		{Pattern: regexp.MustCompile(`Zonesystem Awake`), Pct: 72, Label: "Starting server"},
		{Pattern: regexp.MustCompile(`Load world:`), Pct: 80, Label: "Loading world"},
		{Pattern: regexp.MustCompile(`Loading: Generating locations`), Pct: 88, Label: "Generating world"},
		{Pattern: readyRe, Pct: 100, Label: "Server ready"},
	},
	Parse: parseDownload,
}

var downloadRe = regexp.MustCompile(`Update state \(0x61\) downloading, progress: (\d+(?:\.\d+)?)`)

func parseDownload(line string) (int, string, bool) {
	m := downloadRe.FindStringSubmatch(line)
	if m == nil {
		return 0, "", false
	}
	pct, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, "", false
	}
	return 10 + int(pct*0.6), fmt.Sprintf("Downloading server files (%.0f%%)", pct), true
}

// NewTracker builds the log-following tracker for the named container; the
// caller starts its Run once as a goroutine.
func NewTracker(docker *dockerctl.Client, containerName string) *logtrack.Tracker {
	return logtrack.New(docker, containerName, logtrack.Spec{
		Name:  "valheim",
		Ready: readyRe,
		Join:  connectRe,
		Leave: disconnectRe,
		World: worldRe,
	})
}
