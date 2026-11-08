package main

import (
	"os"
	"time"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/games/palworld"
	"github.com/fiddler110/crowsnest/internal/games/valheim"
	"github.com/fiddler110/crowsnest/internal/games/windrose"
)

// gameTrackers are the background log followers the per-game wiring created.
// serve() starts each with its Run method.
type gameTrackers struct {
	valheim  []*valheim.Tracker
	windrose []*windrose.Tracker
}

// buildGameDefs turns the configured games into fully wired GameDefs: the
// config-driven baseline from games.FromConfig, then each known game's own
// strategies (status, players, info, console, startup progress, cooldown)
// attached by game ID.
//
// This is the one place that knows which games exist. It was extracted from
// serve() unchanged so a characterization test can pin its behaviour; the
// module loader replaces it (see docs/modularization-plan.md).
func buildGameDefs(cfg *config.Config, docker *dockerctl.Client) ([]games.GameDef, gameTrackers) {
	defs := games.FromConfig(cfg.Games, docker)
	var tr gameTrackers
	for i, d := range defs {
		// cfg.Games[i] lines up 1:1 with defs[i]: FromConfig builds defs by
		// iterating cfg.Games in order without filtering or reordering.
		switch d.ID {
		case "windrose":
			// Real status/startup detection (a log-following tracker, no docker exec) plus, when configured,
			// the Windrose+ HTTP/RCON integration for player count and the
			// rich info panel — see docs/implementation-plan.md phases 7
			// and 10.
			wtracker := windrose.NewTracker(docker, d.ContainerName)
			defs[i].Status = wtracker
			tr.windrose = append(tr.windrose, wtracker)
			defs[i].Startup = windrose.Startup
			if wc := cfg.Games[i].Windrose; wc != nil {
				client := &windrose.Client{
					BaseURL:       wc.HTTPAPIURL,
					Password:      os.Getenv(wc.RCONPasswordEnv),
					Docker:        docker,
					ContainerName: d.ContainerName,
				}
				defs[i].Players = client
				defs[i].Info = client
			}
		case "palworld":
			// Palworld's dedicated server REST API doubles as both status
			// probe (reachable == online) and player counter — see
			// docs/implementation-plan.md phase 10. Verified against a real
			// palworld-server-docker container (2026-09-30).
			if pc := cfg.Games[i].Palworld; pc != nil {
				client := &palworld.Client{
					BaseURL:  pc.RESTAPIURL,
					User:     pc.RESTAPIUser,
					Password: os.Getenv(pc.RESTAPIPasswordEnv),
					Docker:   docker,
				}
				if pc.RCONAddr != "" {
					env := pc.RCONPasswordEnv
					if env == "" {
						env = pc.RESTAPIPasswordEnv
					}
					client.RCONAddr = pc.RCONAddr
					client.RCONPassword = os.Getenv(env)
					defs[i].RawConsole = client
				}
				defs[i].Status = client
				defs[i].Players = client
				defs[i].Info = client
				defs[i].PreStop = client
				defs[i].Console = client
			}
			defs[i].Startup = palworld.Startup
			// Bringing it back up seconds after a stop segfaulted it once.
			defs[i].RestartCooldown = 30 * time.Second
		case "valheim":
			// No first-party API: player count comes from tailing the
			// container's own log output for join/leave markers — see
			// docs/implementation-plan.md phase 10. The same tail also
			// reports readiness (starting vs. online) and drives the
			// progress bar; both verified against a real container
			// (2026-09-30), joins/leaves not yet with a real player.
			tracker := valheim.NewTracker(docker, d.ContainerName)
			defs[i].Players = tracker
			defs[i].Info = tracker
			defs[i].Status = tracker
			defs[i].Startup = valheim.Startup
			tr.valheim = append(tr.valheim, tracker)
		}
	}
	return defs, tr
}
