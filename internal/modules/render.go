package modules

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"gopkg.in/yaml.v3"
)

// Runtime is the container half of a module: everything needed to render a
// compose service and the matching guard scope, so the two cannot drift.
// Nothing here can ask for more than the guard allows by default: host
// networking, capabilities, seccomp and fixed addresses are not expressible,
// so a rendered module always fits the default policy envelope.
type Runtime struct {
	RestartCooldown time.Duration `yaml:"restart_cooldown"`

	Image     string        `yaml:"image"` // repository, no tag
	Tag       string        `yaml:"tag"`   // default "latest"
	StopGrace time.Duration `yaml:"stop_grace"`
	Memory    string        `yaml:"memory"` // compose mem_limit, e.g. 10g
	// RAM is the memory the game typically uses, e.g. 6g. It is only a
	// planning figure: a start is refused when the host has less free than
	// this (see internal/memadmit), until the game has run and its measured
	// peak takes over. Unset, memory is used; with neither there is no check.
	// An instance may override it with the reserved option ram.
	RAM string `yaml:"ram"`
	// DataDir is the folder under platform.games_root holding this game's
	// data. An instance may override it with the reserved option data_dir.
	DataDir string        `yaml:"data_dir"`
	Ports   []RuntimePort `yaml:"ports"`
	Data    []DataMount   `yaml:"data"`
	// Env entries are NAME=value. A ${option} in the value is replaced by
	// the instance's value for that option; options not set in config.yaml,
	// and every secret option, become a compose variable
	// ${<ID>_<OPTION>:-<default>} so the value lives in .env.
	Env []string `yaml:"env"`

	// SecOpts are security options the container needs (the Windrose image's
	// Wine runtime needs seccomp=unconfined). They are never a default: the
	// operator's policy must carry an exception naming this game before the
	// guard lets the game be created.
	SecOpts []string `yaml:"secopts"`
	// Networks are extra networks the game joins, each named by an option of
	// the instance (so the operator's LAN network and address are typed in the
	// form, not written into the module). A network whose option is empty is
	// skipped. Same rule as SecOpts: only under a policy exception.
	Networks []RuntimeNetwork `yaml:"networks"`
	// GamesIPv4Option names the option holding a fixed address on the games
	// network itself. Policy exception only, like the rest.
	GamesIPv4Option string `yaml:"games_ipv4_option"`
}

// RuntimeNetwork is an extra network, taken from the instance's options.
type RuntimeNetwork struct {
	NameOption string `yaml:"name_option"`
	IPv4Option string `yaml:"ipv4_option"`
	GwPriority int    `yaml:"gw_priority"` // the highest gets the default route
}

// NetEndpoint is one network a rendered game joins.
type NetEndpoint = dockerctl.NetEndpoint

// ServiceNet is a compose network entry that carries more than the name.
type ServiceNet struct {
	IPv4Address string `yaml:"ipv4_address,omitempty"`
	GwPriority  int    `yaml:"gw_priority,omitempty"`
}

// RuntimePort is one published port. The host port equals the container port
// unless the instance overrides it (reserved option ports, "host:container/proto,...").
type RuntimePort struct {
	Port  int    `yaml:"port"`
	Proto string `yaml:"proto"` // udp (default) or tcp
}

// DataMount is a bind mount of <games_root>/<data_dir>/<Sub> at Path.
// An empty Sub mounts <games_root>/<data_dir> itself.
type DataMount struct {
	Sub  string `yaml:"sub"`
	Path string `yaml:"path"`
}

// Platform is the host-level input to Render.
type Platform struct {
	GamesRoot string // e.g. ${USERDIR} or /srv/games
	// HostGamesRoot is GamesRoot as a literal path, for the guard's scopes;
	// "" means GamesRoot is already literal.
	HostGamesRoot string
	HostIP        string // published-port address; "" = 0.0.0.0
	Network       string // existing docker network; "" = crowsnest-games-net
}

// PlatformFrom reads the platform section of config.yaml.
func PlatformFrom(c config.PlatformConfig) Platform {
	return Platform{GamesRoot: c.GamesRoot, HostGamesRoot: c.HostGamesRoot, HostIP: c.HostIP, Network: c.GamesNetwork}
}

// Service is one rendered compose service (field order is output order).
type Service struct {
	Image         string            `yaml:"image"`
	Profiles      []string          `yaml:"profiles"`
	ContainerName string            `yaml:"container_name"`
	Restart       string            `yaml:"restart"`
	Labels        map[string]string `yaml:"labels"`
	StopGrace     string            `yaml:"stop_grace_period,omitempty"`
	Networks      any               `yaml:"networks"` // []string, or name -> ServiceNet when an address is pinned
	SecurityOpt   []string          `yaml:"security_opt,omitempty"`
	MemLimit      string            `yaml:"mem_limit,omitempty"`
	Ports         []string          `yaml:"ports,omitempty"`
	Environment   []string          `yaml:"environment"`
	Volumes       []string          `yaml:"volumes,omitempty"`
}

// GuardPort and GuardScope marshal to the GUARD_SCOPES JSON the guard reads.
type GuardPort struct {
	HostIP        string `json:"host_ip"`
	HostPort      string `json:"host_port"`
	ContainerPort string `json:"container_port"`
	Proto         string `json:"proto"`
}

type GuardScope struct {
	Name     string            `json:"name"`
	Images   []string          `json:"images"`
	Binds    []string          `json:"binds"`
	Networks []string          `json:"networks"`
	Ports    []GuardPort       `json:"ports"`
	Labels   map[string]string `json:"labels"`
	Exec     bool              `json:"exec"`
	// SecOpts and IPv4 are only ever set for a game the operator's policy names
	// in an exception; the guard refuses the scope otherwise.
	SecOpts []string            `json:"secopts,omitempty"`
	IPv4    map[string][]string `json:"ipv4,omitempty"`
}

// Rendered is everything one game instance needs on the host.
type Rendered struct {
	ID      string
	Service Service
	// Repo and Tag are the image as the module and options name it. Service.Image
	// is Repo:Tag until Pin names one exact image by digest.
	Repo, Tag string
	Scope     GuardScope
	// EnvVars are the .env variables the service reads, name -> default
	// ("" for secrets and unset values), in a stable order.
	EnvVars []EnvVar

	// What the dashboard needs to create the container itself: literal bind
	// mounts (host:container), memory and stop grace.
	binds     []string
	nets      []NetEndpoint
	secopts   []string
	memory    string
	stopGrace time.Duration
	ports     []renderPort
	hostIP    string
}

type EnvVar struct {
	Name, Default string
	Secret        bool
}

var optRef = regexp.MustCompile(`\$\{([a-z][a-z0-9_]*)\}`)

// Render turns a module plus one game's config into its compose service and
// guard scope. It errors if the module has no runtime section.
func (m *Manifest) Render(g config.GameConfig, p Platform) (*Rendered, error) {
	rt := m.Runtime
	image, tag := rt.Image, rt.Tag
	if v := g.Options["image"]; v != "" {
		image = v
	}
	if v := g.Options["tag"]; v != "" {
		tag = v
	}
	if image == "" {
		return nil, fmt.Errorf("game %q: module %q has no runtime.image; set options.image", g.ID, m.ID)
	}
	if tag == "" {
		tag = "latest"
	}
	if p.GamesRoot == "" {
		return nil, fmt.Errorf("game %q: platform.games_root is not set", g.ID)
	}
	network := p.Network
	if network == "" {
		network = "crowsnest-games-net"
	}
	hostIP := p.HostIP
	if hostIP == "" {
		hostIP = "0.0.0.0"
	}
	dataDir := rt.DataDir
	if v := g.Options["data_dir"]; v != "" {
		dataDir = v
	}
	if dataDir == "" {
		dataDir = m.Name
	}
	if strings.Contains(dataDir, "..") || strings.HasPrefix(dataDir, "/") {
		return nil, fmt.Errorf("game %q: data_dir %q must be a plain relative folder name", g.ID, dataDir)
	}

	r := &Rendered{ID: g.ID, Repo: image, Tag: tag}
	svc := Service{
		Image: image + ":" + tag, Profiles: []string{g.ID}, ContainerName: g.ContainerName,
		Restart:  "unless-stopped",
		Labels:   map[string]string{"com.centurylinklabs.watchtower.enable": "false"},
		Networks: []string{network}, MemLimit: rt.Memory,
	}
	if rt.StopGrace > 0 {
		svc.StopGrace = rt.StopGrace.String()
		svc.StopGrace = strings.NewReplacer("m0s", "m", "h0m", "h").Replace(svc.StopGrace)
	}
	scope := GuardScope{
		Name: g.ID, Images: []string{image}, Networks: []string{network},
		Ports: []GuardPort{}, Binds: []string{}, Labels: svc.Labels, Exec: true,
	}
	// optVal is an instance's option, or the module's default for it.
	optVal := func(key string) string {
		if key == "" {
			return ""
		}
		if v, set := g.Options[key]; set {
			return strings.TrimSpace(v)
		}
		for _, o := range m.Options {
			if o.Key == key {
				return o.Default
			}
		}
		return ""
	}
	nets := []NetEndpoint{{Name: network, IPv4: optVal(rt.GamesIPv4Option)}}
	for _, rn := range rt.Networks {
		name := optVal(rn.NameOption)
		if name == "" || name == network {
			continue
		}
		nets = append(nets, NetEndpoint{Name: name, IPv4: optVal(rn.IPv4Option), GwPriority: rn.GwPriority})
	}
	for _, n := range nets {
		if n.IPv4 != "" || n.GwPriority != 0 || len(nets) > 1 {
			cfg := map[string]ServiceNet{}
			for _, e := range nets {
				cfg[e.Name] = ServiceNet{IPv4Address: e.IPv4, GwPriority: e.GwPriority}
			}
			svc.Networks = cfg
			break
		}
	}
	for _, n := range nets[1:] {
		scope.Networks = append(scope.Networks, n.Name)
	}
	for _, n := range nets {
		if n.IPv4 != "" {
			if scope.IPv4 == nil {
				scope.IPv4 = map[string][]string{}
			}
			scope.IPv4[n.Name] = append(scope.IPv4[n.Name], n.IPv4)
		}
	}
	for _, o := range rt.SecOpts {
		svc.SecurityOpt = append(svc.SecurityOpt, o)
		scope.SecOpts = append(scope.SecOpts, o)
		if strings.Contains(o, "=") { // the guard lists both spellings of a security option
			scope.SecOpts = append(scope.SecOpts, strings.Replace(o, "=", ":", 1))
		}
	}
	r.nets, r.secopts = nets, svc.SecurityOpt

	ports, err := m.ports(g)
	if err != nil {
		return nil, err
	}
	r.memory, r.stopGrace, r.ports, r.hostIP = rt.Memory, rt.StopGrace, ports, hostIP
	for _, pt := range ports {
		svc.Ports = append(svc.Ports, fmt.Sprintf("%s:%d:%d/%s", hostIP, pt.host, pt.container, pt.proto))
		scope.Ports = append(scope.Ports, GuardPort{HostIP: hostIP, HostPort: strconv.Itoa(pt.host),
			ContainerPort: strconv.Itoa(pt.container), Proto: pt.proto})
	}
	for _, d := range rt.Data {
		host := strings.TrimRight(p.GamesRoot, "/") + "/" + dataDir
		if d.Sub != "" {
			host += "/" + strings.Trim(d.Sub, "/")
		}
		svc.Volumes = append(svc.Volumes, host+":"+d.Path)
		scopeHost := host
		if p.HostGamesRoot != "" {
			scopeHost = strings.TrimRight(p.HostGamesRoot, "/") + strings.TrimPrefix(host, strings.TrimRight(p.GamesRoot, "/"))
		}
		scope.Binds = append(scope.Binds, scopeHost)
		r.binds = append(r.binds, scopeHost+":"+d.Path)
	}

	seen := map[string]bool{}
	addVar := func(v EnvVar) {
		if !seen[v.Name] {
			seen[v.Name] = true
			r.EnvVars = append(r.EnvVars, v)
		}
	}
	svc.Environment = append(svc.Environment, "TZ=${TZ:-UTC}")
	addVar(EnvVar{Name: "TZ", Default: "UTC"})
	opts := map[string]Option{}
	for _, o := range m.Options {
		opts[o.Key] = o
	}
	for _, e := range rt.Env {
		name, val, ok := strings.Cut(e, "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("module %q: runtime.env entry %q must be NAME=value", m.ID, e)
		}
		var bad error
		val = optRef.ReplaceAllStringFunc(val, func(ref string) string {
			key := ref[2 : len(ref)-1]
			o, known := opts[key]
			if !known {
				bad = fmt.Errorf("module %q: runtime.env %s uses undeclared option %q", m.ID, name, key)
				return ref
			}
			envName := strings.ToUpper(strings.ReplaceAll(g.ID, "-", "_") + "_" + key)
			def := o.Default
			if v, set := g.Options[key]; set && !o.Secret {
				return strings.ReplaceAll(v, "$", "$$")
			}
			addVar(EnvVar{Name: envName, Default: def, Secret: o.Secret})
			if o.Secret {
				return "${" + envName + ":-}"
			}
			return "${" + envName + ":-" + strings.ReplaceAll(def, "$", "$$") + "}"
		})
		if bad != nil {
			return nil, bad
		}
		svc.Environment = append(svc.Environment, name+"="+val)
	}
	r.Service, r.Scope = svc, scope
	return r, nil
}

type renderPort struct {
	host, container int
	proto           string
}

// ports resolves the published ports: the instance's "ports" option
// ("host:container/proto,...") if set, else the module's own.
func (m *Manifest) ports(g config.GameConfig) ([]renderPort, error) {
	var out []renderPort
	if spec := g.Options["ports"]; spec != "" {
		for _, item := range strings.Split(spec, ",") {
			item = strings.TrimSpace(item)
			proto := "udp"
			if body, pr, ok := strings.Cut(item, "/"); ok {
				item, proto = body, pr
			}
			h, c, hasC := strings.Cut(item, ":")
			if !hasC {
				c = h
			}
			hp, err1 := strconv.Atoi(h)
			cp, err2 := strconv.Atoi(c)
			if err1 != nil || err2 != nil || hp < 1 || hp > 65535 || cp < 1 || cp > 65535 || (proto != "udp" && proto != "tcp") {
				return nil, fmt.Errorf("game %q: options.ports entry %q must look like 27015 or 27016:27015/udp", g.ID, item)
			}
			out = append(out, renderPort{hp, cp, proto})
		}
		return out, nil
	}
	for _, pt := range m.Runtime.Ports {
		proto := pt.Proto
		if proto == "" {
			proto = "udp"
		}
		out = append(out, renderPort{pt.Port, pt.Port, proto})
	}
	return out, nil
}

// ComposeFile renders services as one compose document (the same shape as
// the hand-written games.compose.yaml).
func ComposeFile(rs []*Rendered, network string) ([]byte, error) {
	if network == "" {
		network = "crowsnest-games-net"
	}
	services := &yaml.Node{Kind: yaml.MappingNode}
	for _, r := range rs {
		var n yaml.Node
		if err := n.Encode(r.Service); err != nil {
			return nil, err
		}
		services.Content = append(services.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: r.ID}, &n)
	}
	var out strings.Builder
	out.WriteString("# Generated by `crowsnest render` from module.yaml files. Do not edit by hand.\nname: crowsnest-games\n\nservices:\n")
	b, err := yaml.Marshal(services)
	if err != nil {
		return nil, err
	}
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		out.WriteString("  " + l + "\n")
	}
	out.WriteString("\nnetworks:\n  " + network + ":\n    external: true\n")
	return []byte(out.String()), nil
}

// Ref is the tag reference a pull resolves (repo:tag).
func (r *Rendered) Ref() string { return r.Repo + ":" + r.Tag }

// Pin makes the service (and the container Spec creates) run exactly the image
// with this digest (sha256:...) instead of whatever the tag points at now. An
// empty digest goes back to the tag. The guard scope is unchanged: it names
// repositories, never tags or digests.
func (r *Rendered) Pin(digest string) {
	if digest == "" {
		r.Service.Image = r.Ref()
		return
	}
	r.Service.Image = r.Repo + "@" + digest
}

// ScopesJSON renders GUARD_SCOPES for the given games.
func ScopesJSON(rs []*Rendered) ([]byte, error) {
	scopes := make([]GuardScope, 0, len(rs))
	for _, r := range rs {
		scopes = append(scopes, r.Scope)
	}
	return json.MarshalIndent(scopes, "", "  ")
}

// Spec is the container the dashboard creates for this game. lookup supplies
// the value of each compose variable the service reads (the panel's secret
// store, then its own environment); a missing one falls back to the default
// written in the service, or empty.
func (r *Rendered) Spec(lookup func(name string) (string, bool)) (dockerctl.CreateSpec, error) {
	spec := dockerctl.CreateSpec{
		Name: r.Service.ContainerName, Image: r.Service.Image, Labels: r.Service.Labels,
		Network: r.nets[0].Name, Networks: r.nets, SecOpts: r.secopts, StopTimeout: int(r.stopGrace.Seconds()), Binds: r.binds,
	}
	if spec.Name == "" {
		spec.Name = r.ID
	}
	for _, e := range r.Service.Environment {
		spec.Env = append(spec.Env, expandCompose(e, lookup))
	}
	for _, p := range r.ports {
		spec.Ports = append(spec.Ports, dockerctl.PortBinding{HostIP: r.hostIP, HostPort: p.host, ContainerPort: p.container, Proto: p.proto})
	}
	if r.memory != "" {
		n, err := parseSize(r.memory)
		if err != nil {
			return spec, err
		}
		spec.MemoryBytes = n
	}
	return spec, nil
}

// expandCompose expands ${NAME}, ${NAME:-default} and $$ the way compose does.
func expandCompose(s string, lookup func(string) (string, bool)) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '$' && i+1 < len(s) && s[i+1] == '$':
			out.WriteByte('$')
			i++
		case s[i] == '$' && i+1 < len(s) && s[i+1] == '{':
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				out.WriteString(s[i:])
				return out.String()
			}
			name, def, _ := strings.Cut(s[i+2:i+end], ":-")
			if v, ok := lookup(name); ok && v != "" {
				out.WriteString(v)
			} else {
				out.WriteString(strings.ReplaceAll(def, "$$", "$"))
			}
			i += end
		default:
			out.WriteByte(s[i])
		}
	}
	return out.String()
}

// SizeBytes parses sizes like 512m or 10g (k, m, g; no suffix is bytes).
func SizeBytes(field, s string) (int64, error) {
	n, err := parseSize(s)
	if err != nil {
		return 0, fmt.Errorf("%s %q must look like 512m or 10g", field, s)
	}
	return n, nil
}

func parseSize(s string) (int64, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	mult := int64(1)
	for suffix, m := range map[string]int64{"k": 1 << 10, "m": 1 << 20, "g": 1 << 30} {
		if strings.HasSuffix(t, suffix) {
			mult, t = m, strings.TrimSuffix(t, suffix)
		}
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("runtime.memory %q must look like 512m or 10g", s)
	}
	return n * mult, nil
}
