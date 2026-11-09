package modules

import (
	"bytes"
	"embed"
	"fmt"
)

//go:embed bundled/*/module.yaml
var bundledFS embed.FS

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
		s.Register(m.ID, m.Wire())
	}
}
