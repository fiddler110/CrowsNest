package modules

import "github.com/fiddler110/crowsnest/internal/dockerguard"

// DefaultNetwork is the games network when platform.games_network is not set.
const DefaultNetwork = "crowsnest-games-net"

// PolicyDefaults is what a policy that leaves out images or networks gets: the
// images the bundled modules declare (a module installed from a URL is not
// included: its image goes in the policy, by name) and the games network. The
// guard and the panel both use it, so the panel's preview matches the guard.
func PolicyDefaults(p Platform) dockerguard.Defaults {
	d := dockerguard.Defaults{Network: p.Network}
	if d.Network == "" {
		d.Network = DefaultNetwork
	}
	for _, m := range Bundled().Manifests() {
		if m.Runtime.Image != "" {
			d.Images = append(d.Images, m.Runtime.Image)
		}
	}
	return d
}
