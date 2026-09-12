// Package games defines the per-game abstraction that lets CrowsNest control
// different game server containers through one shared code path: a static
// GameDef plus pluggable strategies for status detection, player counting,
// log formatting, and startup progress.
package games

import (
	"context"
	"regexp"
)

// Status is a coarse container/game lifecycle state, independent of how a
// particular game exposes it (log marker, log pattern, or Docker state only).
type Status int

const (
	StatusOffline Status = iota
	StatusStarting
	StatusOnline
	StatusUnknown
)

func (s Status) String() string {
	switch s {
	case StatusOffline:
		return "offline"
	case StatusStarting:
		return "starting"
	case StatusOnline:
		return "online"
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
}

// InfoProvider supplies extra per-game panel data (world time, weather,
// multipliers, memory, etc.) beyond the basic player count. Optional — most
// games won't implement this.
type InfoProvider interface {
	Info(ctx context.Context) (map[string]any, bool)
}

// GameDef is one game's static identity plus its pluggable strategies.
type GameDef struct {
	ID            string
	DisplayName   string
	ContainerName string
	Image         string

	ComposeFile    string
	ComposeProfile string
	ComposeService string

	NightShutdown bool

	Status       StatusChecker
	Players      PlayerCounter
	Startup      *StartupMatcher
	LogFormatter LogLineFormatter
	Info         InfoProvider
}
