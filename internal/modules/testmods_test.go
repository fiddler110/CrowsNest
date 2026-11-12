package modules

import (
	"embed"
	"io/fs"
)

// Test copies of modules that are no longer bundled (see modtest). The package's own tests cannot import modtest
// (it imports this package), so they embed the same files.
//
//go:embed modtest/mods/*/module.yaml
var testMods embed.FS

func init() {
	sub, err := fs.Sub(testMods, "modtest/mods")
	if err != nil {
		panic(err)
	}
	AddBundled(sub)
}
