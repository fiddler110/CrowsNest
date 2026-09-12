package games

import (
	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
)

// FromConfig builds one GameDef per configured game, wired with the Phase 3
// baseline strategies (docker-ps-only status, always-undetermined player
// count). Real per-game packages (Phase 10) construct richer GameDefs
// directly; this is the fallback that makes every configured game
// start/stop-able before that integration work lands.
func FromConfig(cfgs []config.GameConfig, docker *dockerctl.Client) []GameDef {
	defs := make([]GameDef, 0, len(cfgs))
	for _, g := range cfgs {
		defs = append(defs, GameDef{
			ID:             g.ID,
			DisplayName:    g.DisplayName,
			ContainerName:  g.ContainerName,
			ComposeFile:    g.ComposeFile,
			ComposeProfile: g.ComposeProfile,
			ComposeService: g.ComposeService,
			Status:         &DockerStatusChecker{Docker: docker},
			Players:        UnknownPlayerCounter{},
		})
	}
	return defs
}

// DockerTarget converts a GameDef's container/compose identity into a
// dockerctl.Target for Start/Stop calls.
func (d GameDef) DockerTarget() dockerctl.Target {
	return dockerctl.Target{
		ContainerName:  d.ContainerName,
		ComposeFile:    d.ComposeFile,
		ComposeProfile: d.ComposeProfile,
		ComposeService: d.ComposeService,
	}
}
