package modules

import (
	"os"

	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/games/windrose"
)

// Bundled returns the modules that ship in the binary: Palworld and Valheim
// (embedded module.yaml files) and Windrose (Go, until its adapter lands). Their wiring moved here unchanged from cmd/crowsnest; the golden
// tests there pin it.
func Bundled() *Set {
	s := NewSet()
	s.Register("windrose", wireWindrose)
	registerEmbedded(s) // valheim, palworld
	return s
}

func wireWindrose(def *games.GameDef, env Env) []Runner {
	// Real status/startup detection (a log-following tracker, no docker exec)
	// plus, when configured, the Windrose+ HTTP/RCON integration for player
	// count and the rich info panel — docs/implementation-plan.md phases 7
	// and 10.
	tracker := windrose.NewTracker(env.Docker, def.ContainerName)
	def.Status = tracker
	def.Startup = windrose.Startup
	// Options (legacy windrose: block is folded into them by config):
	// http_api_url, rcon_password_env.
	if url := env.Config.Options["http_api_url"]; url != "" {
		client := &windrose.Client{
			BaseURL:       url,
			Password:      os.Getenv(env.Config.Options["rcon_password_env"]),
			Docker:        env.Docker,
			ContainerName: def.ContainerName,
		}
		def.Players = client
		def.Info = client
	}
	return []Runner{tracker}
}
