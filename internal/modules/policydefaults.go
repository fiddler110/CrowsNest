package modules

import (
	"fmt"

	"github.com/fiddler110/crowsnest/internal/dockerguard"
)

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
	d.ModulePorts = map[string][]string{}
	for _, m := range Bundled().Manifests() {
		if m.Runtime.Image != "" {
			d.Images = append(d.Images, m.Runtime.Image)
		}
		for _, pt := range m.Runtime.Ports {
			d.ModulePorts[m.ID] = append(d.ModulePorts[m.ID], PortSpec(pt))
		}
	}
	return d
}

// PortSpec is a module port written as the policy writes it, "25565/tcp".
func PortSpec(p RuntimePort) string {
	proto := p.Proto
	if proto == "" {
		proto = "udp"
	}
	return fmt.Sprintf("%d/%s", p.Port, proto)
}
