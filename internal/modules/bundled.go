package modules

import (
	"os"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/games/palworld"
	"github.com/fiddler110/crowsnest/internal/games/valheim"
	"github.com/fiddler110/crowsnest/internal/games/windrose"
)

// Bundled returns the modules that ship in the binary: Palworld, Valheim and
// Windrose. Their wiring moved here unchanged from cmd/crowsnest; the golden
// tests there pin it.
func Bundled() *Set {
	s := NewSet()
	s.Register("windrose", wireWindrose)
	s.Register("palworld", wirePalworld)
	s.Register("valheim", wireValheim)
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
	if wc := env.Config.Windrose; wc != nil {
		client := &windrose.Client{
			BaseURL:       wc.HTTPAPIURL,
			Password:      os.Getenv(wc.RCONPasswordEnv),
			Docker:        env.Docker,
			ContainerName: def.ContainerName,
		}
		def.Players = client
		def.Info = client
	}
	return []Runner{tracker}
}

func wirePalworld(def *games.GameDef, env Env) []Runner {
	// Palworld's dedicated server REST API doubles as both status probe
	// (reachable == online) and player counter — docs/implementation-plan.md
	// phase 10. Verified against a real palworld-server-docker container
	// (2026-09-30).
	if pc := env.Config.Palworld; pc != nil {
		client := &palworld.Client{
			BaseURL:  pc.RESTAPIURL,
			User:     pc.RESTAPIUser,
			Password: os.Getenv(pc.RESTAPIPasswordEnv),
			Docker:   env.Docker,
		}
		if pc.RCONAddr != "" {
			pw := pc.RCONPasswordEnv
			if pw == "" {
				pw = pc.RESTAPIPasswordEnv
			}
			client.RCONAddr = pc.RCONAddr
			client.RCONPassword = os.Getenv(pw)
			def.RawConsole = client
		}
		def.Status = client
		def.Players = client
		def.Info = client
		def.PreStop = client
		def.Console = client
	}
	def.Startup = palworld.Startup
	// Bringing it back up seconds after a stop segfaulted it once.
	def.RestartCooldown = 30 * time.Second
	return nil
}

func wireValheim(def *games.GameDef, env Env) []Runner {
	// No first-party API: player count comes from tailing the container's own
	// log output for join/leave markers — docs/implementation-plan.md phase
	// 10. The same tail also reports readiness (starting vs. online) and
	// drives the progress bar; both verified against a real container
	// (2026-09-30), joins/leaves not yet with a real player.
	tracker := valheim.NewTracker(env.Docker, def.ContainerName)
	def.Players = tracker
	def.Info = tracker
	def.Status = tracker
	def.Startup = valheim.Startup
	return []Runner{tracker}
}
