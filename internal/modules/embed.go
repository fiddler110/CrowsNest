package modules

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"sync"

	"github.com/fiddler110/crowsnest/internal/games"
)

//go:embed bundled/*/module.yaml
var bundledFS embed.FS

// extensions are Go hooks a bundled module may add on top of its manifest,
// for the few things YAML cannot express (Windrose+'s cookie-session API). The
// manifest wiring always runs first; an extension only refines the result.
var extensions = map[string]WireFunc{}

// registerEmbedded registers every module.yaml shipped in the binary. A bad
// embedded manifest is a build mistake, so it panics (the tests catch it).
func registerEmbedded(s *Set) {
	sub, err := fs.Sub(bundledFS, "bundled")
	if err != nil {
		panic(err)
	}
	registerFS(s, sub)
	extraMu.Lock()
	defer extraMu.Unlock()
	for _, x := range extraFS {
		registerFS(s, x)
	}
}

var (
	extraMu sync.Mutex
	extraFS []fs.FS
)

// AddBundled makes the modules in fsys (<id>/module.yaml) part of what Bundled returns, as if they shipped in the
// binary. It exists for tests, which exercise the engine with modules that are no longer bundled (see modtest), and
// for forks that want their own built-in modules. Call it from init: it affects every Set made afterwards.
func AddBundled(fsys fs.FS) {
	extraMu.Lock()
	defer extraMu.Unlock()
	extraFS = append(extraFS, fsys)
}

// registerFS registers every <id>/module.yaml found at the top of fsys.
func registerFS(s *Set, fsys fs.FS) {
	files, err := fs.ReadDir(fsys, ".")
	if err != nil {
		panic(err)
	}
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f.Name()+"/module.yaml")
		if err != nil {
			panic(err)
		}
		m, err := Parse(bytes.NewReader(b))
		if err != nil {
			panic(fmt.Sprintf("bundled module %s: %v", f.Name(), err))
		}
		if m.ID != f.Name() {
			panic(fmt.Sprintf("bundled module dir %s != id %s", f.Name(), m.ID))
		}
		wire := m.Wire()
		if ext := extensions[m.ID]; ext != nil {
			base := wire
			wire = func(def *games.GameDef, env Env) []Runner {
				return append(base(def, env), ext(def, env)...)
			}
		}
		s.Register(m.ID, wire)
		s.manifests[m.ID] = m
	}
}
