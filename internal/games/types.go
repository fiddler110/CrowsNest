// Package games defines the per-game abstraction that lets CrowsNest control
// different game server containers through one shared code path: a static
// GameDef plus pluggable strategies for status detection, player counting,
// log formatting, and startup progress.
package games

import (
	"context"
	"errors"
	"github.com/fiddler110/crowsnest/internal/gamefiles"
	"regexp"
	"time"
)

// Status is a coarse container/game lifecycle state, independent of how a
// particular game exposes it (log marker, log pattern, or Docker state only).
type Status int

const (
	StatusOffline Status = iota
	StatusStarting
	StatusOnline
	StatusUnknown
	// StatusStopping is reported by the web layer while a stop is in
	// progress; no StatusChecker returns it.
	StatusStopping
)

func (s Status) String() string {
	switch s {
	case StatusOffline:
		return "offline"
	case StatusStarting:
		return "starting"
	case StatusOnline:
		return "online"
	case StatusStopping:
		return "stopping"
	default:
		return "unknown"
	}
}

// StatusChecker determines a game's lifecycle state from live container
// state (and, for some games, from its log output).
type StatusChecker interface {
	Check(ctx context.Context, containerName string) (Status, error)
}

// PlayerCounter reports how many players are currently connected to a game.
//
// ok=false means "could not be determined" (auth failure, unreachable,
// parse error, container not running) — callers MUST treat ok=false as
// unknown, never as zero. This is the interface the exclusivity manager
// depends on to decide whether switching games is safe.
type PlayerCounter interface {
	PlayerCount(ctx context.Context) (count int, names []string, ok bool)
}

// LogLineFormatter turns one raw container log line into an SSE event type
// ("message" | "warn" | "error" | "verbose") plus display text.
type LogLineFormatter interface {
	Format(raw string) (event string, text string)
}

// Milestone maps a log-line pattern to a startup-progress percentage/label.
type Milestone struct {
	Pattern *regexp.Regexp
	Pct     int
	Label   string
}

// StartupMatcher drives a startup-progress SSE stream by matching container
// log lines against an ordered list of milestones. A nil *StartupMatcher on
// a GameDef means that game has no progress bar — just a status badge.
type StartupMatcher struct {
	Milestones []Milestone

	// Parse, if set, is tried on every line before Milestones, for progress
	// that has to be read out of the line itself (e.g. a download
	// percentage) rather than matched against a fixed pattern.
	Parse func(line string) (pct int, label string, ok bool)
}

// InfoProvider supplies extra per-game panel data (world time, weather,
// multipliers, memory, etc.) beyond the basic player count. Optional — most
// games won't implement this.
type InfoProvider interface {
	Info(ctx context.Context) (map[string]any, bool)
}

// StopPreparer is run just before a game's container is stopped on purpose
// (manual stop, switch, idle or night shutdown): warn players and save the
// world, so a stop never relies on the container's own SIGTERM handling
// alone. It is best-effort — an error is logged and the stop goes ahead.
type StopPreparer interface {
	PrepareStop(ctx context.Context) error
}

// ConsoleField is one argument of a ConsoleAction.
type ConsoleField struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Optional bool   `json:"optional,omitempty"`
}

// ConsoleAction is one fixed admin command a game offers on the dashboard:
// the server decides what runs, the admin only fills in the arguments.
type ConsoleAction struct {
	ID     string         `json:"id"`
	Label  string         `json:"label"`
	Fields []ConsoleField `json:"fields,omitempty"`
	Danger bool           `json:"danger,omitempty"`
}

// ErrBadInput marks a console argument the game rejected (as opposed to the
// game being unreachable); its message is safe to show to the admin.
var ErrBadInput = errors.New("bad input")

// Console is a game's set of fixed admin actions. Run validates args itself.
type Console interface {
	Actions() []ConsoleAction
	Run(ctx context.Context, action string, args map[string]string) (string, error)
}

// RawConsole sends an arbitrary command line to the game (RCON). The web
// layer only exposes it when an admin has switched the raw console on.
type RawConsole interface {
	Raw(ctx context.Context, command string) (string, error)
}

// ConnectLister gives labelled join values read from a running game.
type ConnectLister interface {
	ConnectValues() []ConnectSecret
}

// GameDef is one game's static identity plus its pluggable strategies.
type GameDef struct {
	ID            string
	DisplayName   string
	ContainerName string
	Image         string

	NightShutdown bool

	// ConnectAddress/ConnectNote are optional, display-only connection
	// details for the dashboard card (see config.GameConfig). Empty means
	// show nothing.
	ConnectAddress string
	ConnectNote    string

	// ConnectSecrets are labelled values (join password, invite code) shown
	// under the address, already resolved from the environment. Entries whose
	// variable is unset or empty are dropped.
	ConnectSecrets []ConnectSecret

	// Live supplies connect values that only exist while the server runs
	// (a crossplay join code printed in its log). Nil for most games.
	Live ConnectLister

	// Accent is the card's accent colour ("#rrggbb") from the game's module;
	// empty keeps the dashboard's default.
	Accent string

	// RestartCooldown is the minimum time between stopping this game and
	// starting it again; zero means no limit. Some servers (Palworld)
	// crash if brought back up seconds after a shutdown.
	RestartCooldown time.Duration

	// RAMEstimate is the memory in bytes the game is declared to need, from
	// its module (runtime.ram) or the instance's ram option. Zero means
	// undeclared. Memory admission prefers the measured peak once known.
	RAMEstimate uint64

	Status       StatusChecker
	Players      PlayerCounter
	Startup      *StartupMatcher
	LogFormatter LogLineFormatter
	Info         InfoProvider
	PreStop      StopPreparer
	Console      Console
	RawConsole   RawConsole

	// Backup is how to back this game up, nil if it isn't configured.
	Backup *BackupSpec

	// Files are the config files admins may edit from the dashboard (the module's files: block).
	Files []gamefiles.Spec
}

// BackupSpec mirrors config.BackupConfig.
type BackupSpec struct {
	Exec    []string
	ListDir string
	// LocalDir is the game's backup folder as the panel sees it. When set, the
	// panel lists and prunes it directly and ListDir is unused.
	LocalDir   string
	BeforeStop bool
	Keep       int
	// CanRestore is true when the game can restore a backup from its folder.
	CanRestore bool
}

// ConnectSecret is a labelled value shown on a game's dashboard card.
type ConnectSecret struct {
	Label string `json:"label"`
	Value string `json:"value"`
}
