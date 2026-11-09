// Package modules turns configured games into fully wired games.GameDefs.
//
// A module knows how to attach one game's strategies (status, players, info,
// console, startup progress, cooldown) to the config-driven baseline GameDef.
// Modules are looked up by game ID, so the core never names a game. This is
// phase 1 of docs/modularization-plan.md: bundled modules register here as Go
// wiring; a manifest-driven loader (module.yaml) will register the same way.
package modules

import (
	"context"
	"fmt"
	"sort"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

// Runner is a background worker a module needs for the life of the process
// (for example a log follower). Build returns them; serve() starts each with
// go r.Run(ctx).
type Runner interface {
	Run(ctx context.Context)
}

// Env is what a module may use while wiring one game.
type Env struct {
	Docker *dockerctl.Client
	Config config.GameConfig
}

// WireFunc attaches the module's strategies to def (already holding the
// config-driven baseline) and returns any background Runners it created.
type WireFunc func(def *games.GameDef, env Env) []Runner

// Set is a collection of modules keyed by game ID.
type Set struct {
	wire map[string]WireFunc
}

// NewSet returns an empty Set.
func NewSet() *Set { return &Set{wire: map[string]WireFunc{}} }

// Register adds a module for id. It panics on an empty or duplicate id, since
// that is a programming error in the bundled set, not a runtime condition.
func (s *Set) Register(id string, fn WireFunc) {
	if id == "" || fn == nil {
		panic("modules: Register needs an id and a WireFunc")
	}
	if _, dup := s.wire[id]; dup {
		panic(fmt.Sprintf("modules: duplicate module %q", id))
	}
	s.wire[id] = fn
}

// IDs lists the registered module IDs, sorted.
func (s *Set) IDs() []string {
	out := make([]string, 0, len(s.wire))
	for id := range s.wire {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Build turns the configured games into wired GameDefs: the config-driven
// baseline from games.FromConfig, then the module registered for each game's
// ID (a game with no module keeps the baseline: docker-state status, unknown
// player count). The returned Runners belong to the caller to start.
func (s *Set) Build(cfg *config.Config, docker *dockerctl.Client) ([]games.GameDef, []Runner) {
	defs := games.FromConfig(cfg.Games, docker)
	var runners []Runner
	for i := range defs {
		// cfg.Games[i] lines up 1:1 with defs[i]: FromConfig builds defs by
		// iterating cfg.Games in order without filtering or reordering.
		fn, ok := s.wire[defs[i].ID]
		if !ok {
			continue
		}
		runners = append(runners, fn(&defs[i], Env{Docker: docker, Config: cfg.Games[i]})...)
	}
	return defs, runners
}

// ForConfig returns the module set for a configuration: the bundled modules
// plus any module.yaml directories under cfg.ModulesDir. A local module may
// not reuse a bundled id. Local modules no configured game uses are reported
// through warn (a typo'd game id would otherwise fail silently).
func ForConfig(cfg *config.Config, warn func(format string, args ...any)) (*Set, error) {
	s := Bundled()
	if cfg.ModulesDir == "" {
		return s, nil
	}
	bundled := map[string]bool{}
	for _, id := range s.IDs() {
		bundled[id] = true
	}
	if err := s.LoadDir(cfg.ModulesDir); err != nil {
		return nil, fmt.Errorf("modules_dir %s: %w", cfg.ModulesDir, err)
	}
	used := map[string]bool{}
	for _, g := range cfg.Games {
		used[g.ID] = true
	}
	for _, id := range s.IDs() {
		if !bundled[id] && !used[id] && warn != nil {
			warn("modules: module %q is not used by any game in config.yaml", id)
		}
	}
	return s, nil
}
