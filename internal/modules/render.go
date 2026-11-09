package modules

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/config"
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
	HostIP    string // published-port address; "" = 0.0.0.0
	Network   string // existing docker network; "" = crowsnest-games-net
}

// PlatformFrom reads the platform section of config.yaml.
func PlatformFrom(c config.PlatformConfig) Platform {
	return Platform{GamesRoot: c.GamesRoot, HostIP: c.HostIP, Network: c.GamesNetwork}
}

// Service is one rendered compose service (field order is output order).
type Service struct {
	Image         string            `yaml:"image"`
	Profiles      []string          `yaml:"profiles"`
	ContainerName string            `yaml:"container_name"`
	Restart       string            `yaml:"restart"`
	Labels        map[string]string `yaml:"labels"`
	StopGrace     string            `yaml:"stop_grace_period,omitempty"`
	Networks      []string          `yaml:"networks"`
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
}

// Rendered is everything one game instance needs on the host.
type Rendered struct {
	ID      string
	Service Service
	Scope   GuardScope
	// EnvVars are the .env variables the service reads, name -> default
	// ("" for secrets and unset values), in a stable order.
	EnvVars []EnvVar
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

	r := &Rendered{ID: g.ID}
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

	ports, err := m.ports(g)
	if err != nil {
		return nil, err
	}
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
		scope.Binds = append(scope.Binds, host)
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

// ScopesJSON renders GUARD_SCOPES for the given games.
func ScopesJSON(rs []*Rendered) ([]byte, error) {
	scopes := make([]GuardScope, 0, len(rs))
	for _, r := range rs {
		scopes = append(scopes, r.Scope)
	}
	return json.MarshalIndent(scopes, "", "  ")
}
