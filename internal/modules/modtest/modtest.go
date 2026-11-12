// Package modtest registers test copies of modules that are no longer bundled (Minecraft, Source and Don't Starve
// Together live in the crowsnest-modules repository now). Import it for its side effect from a test file:
//
//	import _ "github.com/fiddler110/crowsnest/internal/modules/modtest"
//
// The copies exercise the engine (log markers, RCON status, backups, restore); they are fixtures, not the published
// modules, and are not compiled into the crowsnest binary.
package modtest

import (
	"embed"
	"io/fs"

	"github.com/fiddler110/crowsnest/internal/modules"
)

//go:embed mods/*/module.yaml
var mods embed.FS

func init() {
	sub, err := fs.Sub(mods, "mods")
	if err != nil {
		panic(err)
	}
	modules.AddBundled(sub)
}
