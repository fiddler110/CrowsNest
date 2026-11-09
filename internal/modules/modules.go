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
	"log"
	"os"
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
	// Lookup resolves a secret by variable name (a password env var). Nil means
	// the process environment; dashboard-enabled games supply their own store
	// so a secret never has to be put into the environment.
	Lookup func(name string) string
}

// Secret returns the value of the named variable, "" when unset.
func (e Env) Secret(name string) string {
	if e.Lookup != nil {
		return e.Lookup(name)
	}
	return os.Getenv(name)
}

// WireFunc attaches the module's strategies to def (already holding the
// config-driven baseline) and returns any background Runners it created.
type WireFunc func(def *games.GameDef, env Env) []Runner

// Set is a collection of modules keyed by game ID.
type Set struct {
	wire      map[string]WireFunc
	manifests map[string]*Manifest
}

// Manifest returns the parsed module.yaml for id, if the module came from one.
func (s *Set) Manifest(id string) (*Manifest, bool) {
	m, ok := s.manifests[id]
	return m, ok
}

// Manifests returns every module that has a manifest, ordered by id.
func (s *Set) Manifests() []*Manifest {
	ids := make([]string, 0, len(s.manifests))
	for id := range s.manifests {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*Manifest, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.manifests[id])
	}
	return out
}

// NewSet returns an empty Set.
func NewSet() *Set { return &Set{wire: map[string]WireFunc{}, manifests: map[string]*Manifest{}} }

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
	var defs []games.GameDef
	var runners []Runner
	for _, g := range cfg.Games {
		d, r := s.BuildOne(cfg, g, docker, nil)
		defs = append(defs, d)
		runners = append(runners, r...)
	}
	return defs, runners
}

// BuildOne wires a single game: its baseline GameDef plus the module for its
// id (or its module: key), if any. cfg supplies the rest of the configuration
// a module may need.
func (s *Set) BuildOne(cfg *config.Config, g config.GameConfig, docker *dockerctl.Client, lookup func(string) string) (games.GameDef, []Runner) {
	def := games.FromConfig([]config.GameConfig{g}, docker)[0]
	id := def.ID
	if g.Module != "" {
		id = g.Module
	}
	fn, ok := s.wire[id]
	if !ok {
		if g.Module != "" {
			log.Printf("modules: game %q asks for module %q, which is not installed; keeping the baseline", def.ID, id)
		}
		return def, nil
	}
	return def, fn(&def, Env{Docker: docker, Config: g, Lookup: lookup})
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
		if g.Module != "" {
			used[g.Module] = true
		}
	}
	for _, id := range s.IDs() {
		if !bundled[id] && !used[id] && warn != nil {
			warn("modules: module %q is not used by any game in config.yaml", id)
		}
	}
	return s, nil
}
