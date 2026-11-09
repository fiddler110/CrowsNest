package dockerguard

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy is the operator-owned envelope around everything the dashboard may
// add. The guard loads it from a file the panel can only read, and applies it
// to every scope that arrives through the managed scopes file, so a panel that
// writes a scope outside the envelope gains nothing: that scope is not loaded.
//
// A managed scope can never carry privileges. Host networking, capabilities,
// security options, volumes, aliases and fixed addresses are not expressible
// in it at all; exec is only possible if the policy says so.
type Policy struct {
	// GamesRoot is the absolute host folder every managed bind must be inside.
	GamesRoot string `yaml:"games_root"`
	// Names are the container names the panel may manage. An entry ending in *
	// is a prefix. Required: without it a managed scope named after any other
	// container on the host would let the panel stop or remove that container.
	Names []string `yaml:"names"`
	// Images are the repositories a managed scope may run (an entry ending in *
	// is a prefix, "*" alone is any image). Required, so "any image" is always
	// a decision written down.
	Images []string `yaml:"images"`
	// Networks the managed containers may join. Required.
	Networks []string `yaml:"networks"`
	// Ports are the host ports (and protocol) a managed scope may publish, as
	// "27000-28999/udp" or "25565/tcp". Required.
	Ports []string `yaml:"ports"`
	// HostIPs, if set, limits the address a port may be published on.
	HostIPs []string `yaml:"host_ips"`
	// Exec lets managed scopes use docker exec (needed for game save-on-stop
	// hooks). Default false.
	Exec bool `yaml:"exec"`
	// Labels the managed scopes may require, beyond the watchtower opt-out.
	Labels []string `yaml:"labels"`
	// MaxScopes bounds how many managed scopes load (default 32).
	MaxScopes int `yaml:"max_scopes"`

	ports []portRange
}

type portRange struct {
	lo, hi int
	proto  string
}

const watchtowerLabel = "com.centurylinklabs.watchtower.enable"

// LoadPolicy reads and validates a policy file.
func LoadPolicy(file string) (*Policy, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	return ParsePolicy(b)
}

// ParsePolicy validates policy YAML. Unknown keys are errors.
func ParsePolicy(b []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if !strings.HasPrefix(p.GamesRoot, "/") || path.Clean(p.GamesRoot) != p.GamesRoot || p.GamesRoot == "/" || strings.ContainsFunc(p.GamesRoot, badBindRune) {
		return nil, fmt.Errorf("policy: games_root must be an absolute, normalised path other than /, not %q", p.GamesRoot)
	}
	for _, f := range []struct {
		name string
		n    int
	}{{"names", len(p.Names)}, {"images", len(p.Images)}, {"networks", len(p.Networks)}, {"ports", len(p.Ports)}} {
		if f.n == 0 {
			return nil, fmt.Errorf("policy: %s must list at least one entry (it is a limit, so it is never implied)", f.name)
		}
	}
	for _, n := range p.Names {
		if n == "*" || !identRe.MatchString(strings.TrimSuffix(n, "*")) {
			return nil, fmt.Errorf("policy: bad container name entry %q", n)
		}
	}
	for _, n := range p.Networks {
		if !identRe.MatchString(n) || n == "host" || n == "none" || strings.HasPrefix(n, "container:") {
			return nil, fmt.Errorf("policy: bad network %q", n)
		}
	}
	for i, img := range p.Images {
		switch {
		case img == "*":
		case strings.HasSuffix(img, "*"):
			// the scopes hold fully qualified repositories, so a prefix must be one too
			if pre := strings.TrimSuffix(img, "*"); !strings.HasSuffix(pre, "/") || !strings.Contains(strings.TrimSuffix(pre, "/"), ".") || strings.ContainsAny(pre, " :@") {
				return nil, fmt.Errorf("policy: an image prefix must be a registry path ending in /*, such as ghcr.io/example/*, not %q", img)
			}
		default:
			repo, tag, digest, err := parseRef(img)
			if err != nil || tag != "" || digest != "" {
				return nil, fmt.Errorf("policy: image entries are repositories without a tag or digest, not %q", img)
			}
			p.Images[i] = repo
		}
	}
	for _, s := range p.Ports {
		pr, err := parsePortRange(s)
		if err != nil {
			return nil, err
		}
		p.ports = append(p.ports, pr)
	}
	for _, h := range p.HostIPs {
		if _, err := netip.ParseAddr(h); err != nil {
			return nil, fmt.Errorf("policy: bad host_ips entry %q", h)
		}
	}
	if p.MaxScopes < 0 || p.MaxScopes > 1000 {
		return nil, errors.New("policy: max_scopes must be between 1 and 1000")
	}
	if p.MaxScopes == 0 {
		p.MaxScopes = 32
	}
	return &p, nil
}

func parsePortRange(s string) (portRange, error) {
	body, proto, ok := strings.Cut(s, "/")
	if !ok {
		return portRange{}, fmt.Errorf("policy: port entry %q must end in /tcp or /udp", s)
	}
	if proto != "tcp" && proto != "udp" {
		return portRange{}, fmt.Errorf("policy: port entry %q must end in /tcp or /udp", s)
	}
	lo, hi, isRange := strings.Cut(body, "-")
	if !isRange {
		hi = lo
	}
	l, err1 := strconv.Atoi(lo)
	h, err2 := strconv.Atoi(hi)
	if err1 != nil || err2 != nil || l < 1 || h > 65535 || l > h {
		return portRange{}, fmt.Errorf("policy: bad port entry %q", s)
	}
	return portRange{l, h, proto}, nil
}

func matchName(list []string, name string) bool {
	for _, e := range list {
		if e == "*" || e == name {
			return true
		}
		if p, ok := strings.CutSuffix(e, "*"); ok && strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func (p *Policy) portOK(pt Port) error {
	if pt.HostPort == "" {
		return errors.New("a managed port must name its host port")
	}
	if pt.Proto != "tcp" && pt.Proto != "udp" {
		return fmt.Errorf("port protocol %s is not allowed", pt.Proto)
	}
	lo, hi, isRange := strings.Cut(pt.HostPort, "-")
	if !isRange {
		hi = lo
	}
	l, _ := strconv.Atoi(lo)
	h, _ := strconv.Atoi(hi)
	ok := false
	for _, r := range p.ports {
		if r.proto == pt.Proto && l >= r.lo && h <= r.hi {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("host port %s/%s is outside the policy's port ranges", pt.HostPort, pt.Proto)
	}
	if len(p.HostIPs) > 0 {
		found := false
		for _, ip := range p.HostIPs {
			if ip == pt.HostIP {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("host_ip %s is not one the policy allows", pt.HostIP)
		}
	}
	return nil
}

// Admit reports why a scope does not fit the envelope, or nil if it does.
// The same check backs the dashboard's "does this fit?" preview and the
// guard's own enforcement when it loads managed scopes.
func (p *Policy) Admit(s *Scope) error {
	if s == nil {
		return errors.New("nil scope")
	}
	if !matchName(p.Names, s.Name) {
		return fmt.Errorf("container name %s is not in the policy's names", s.Name)
	}
	for img := range s.Images {
		if !matchName(p.Images, img) {
			return fmt.Errorf("image %s is not in the policy's images", img)
		}
	}
	for _, b := range s.Binds {
		if !strings.HasPrefix(b, p.GamesRoot+"/") {
			return fmt.Errorf("bind %s is not inside games_root %s", b, p.GamesRoot)
		}
	}
	for n := range s.Networks {
		if !matchName(p.Networks, n) || strings.HasPrefix(n, "container:") || n == "host" {
			return fmt.Errorf("network %s is not in the policy's networks", n)
		}
	}
	if len(s.Networks) == 0 {
		return errors.New("a managed scope must name a network")
	}
	if len(s.Ports) == 0 && len(s.Binds) == 0 {
		return errors.New("a managed scope must publish a port or bind a folder")
	}
	for _, pt := range s.Ports {
		if err := p.portOK(pt); err != nil {
			return err
		}
	}
	if s.Exec && !p.Exec {
		return errors.New("exec is not allowed by the policy")
	}
	for k, v := range s.Labels {
		if k == watchtowerLabel && v == "false" {
			continue
		}
		if !matchName(p.Labels, k) {
			return fmt.Errorf("label %s is not allowed by the policy", k)
		}
	}
	if len(s.Volumes) > 0 || len(s.SecOpts) > 0 || len(s.CapAdd) > 0 || len(s.Aliases) > 0 || len(s.IPv4) > 0 {
		return errors.New("managed scopes cannot carry volumes, security options, capabilities, aliases or fixed addresses")
	}
	return nil
}
