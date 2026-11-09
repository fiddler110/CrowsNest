package modules

import (
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/games/windrose"
)

// Bundled returns the modules that ship in the binary: Palworld, Valheim and
// Windrose, each an embedded module.yaml (bundled/<id>/). The golden tests in
// cmd/crowsnest pin their wiring.
func Bundled() *Set {
	s := NewSet()
	registerEmbedded(s)
	return s
}

func init() { extensions["windrose"] = extendWindrose }

// extendWindrose adds the optional Windrose+ integration to the manifest
// wiring: its dashboard API feeds the rich info panel, player names and the
// admin console (kick, ban, ...). The player count comes from the game log
// (players_source: log, the default) and is cross-checked against the mod;
// with windrose_plus the mod is the source and the log is the cross-check.
func extendWindrose(def *games.GameDef, env Env) []Runner {
	url := env.Config.Options["http_api_url"]
	if url == "" {
		return nil
	}
	client := &windrose.Client{
		BaseURL:       url,
		Password:      env.Secret(env.Config.Options["rcon_password_env"]),
		Docker:        env.Docker,
		ContainerName: def.ContainerName,
	}
	def.Info = client
	def.Console = client
	def.RawConsole = client
	logCount := def.Players
	if env.Config.Options["players_source"] == "windrose_plus" {
		def.Players = &comparingCounter{name: "windrose", primary: client, other: logCount}
	} else {
		def.Players = &comparingCounter{name: "windrose", primary: logCount, other: client, namesFromOther: true}
	}
	return nil
}
