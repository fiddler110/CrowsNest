package modules

import (
	"bytes"
	"embed"
	"fmt"

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
	files, err := bundledFS.ReadDir("bundled")
	if err != nil {
		panic(err)
	}
	for _, f := range files {
		b, err := bundledFS.ReadFile("bundled/" + f.Name() + "/module.yaml")
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
