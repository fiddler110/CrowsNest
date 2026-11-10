package dockerguard

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path"
	"slices"
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
	// is a prefix. Optional: when it is left out, any name is allowed but the
	// guard only acts on containers labelled crowsnest.managed=true, so a scope
	// named after another container on the host still reaches nothing. When
	// it is set, only those names are allowed (and the label is not required).
	Names []string `yaml:"names"`
	// Images are the repositories a managed scope may run (an entry ending in *
	// is a prefix, "*" alone is any image). The entry "@modules" stands for the
	// images the bundled modules declare. Left out, it is just "@modules", so
	// only the images the modules were built for are allowed, and "any image"
	// is always a decision written down.
	Images []string `yaml:"images"`
	// Networks the managed containers may join. Left out, it is the games
	// network of the app's own config (platform.games_network).
	Networks []string `yaml:"networks"`
	// Ports are the host ports (and protocol) a managed scope may publish, as
	// "27000-28999/udp" or "25565/tcp". Optional: the ports of each module the
	// operator allowed are added to it, so this is only for ports beyond those.
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
	// PinDigests makes every create from a managed scope name its image by
	// digest (repo@sha256:...), so an upstream push to a tag cannot change what
	// a dashboard game runs. Pulls by tag stay allowed (that is how a new digest
	// is found). The operator's own GUARD_SCOPES are not affected.
	PinDigests bool `yaml:"pin_digests"`
	// Exceptions let one named container do what the envelope otherwise never
	// allows (a LAN address, a pinned IPv4, a relaxed seccomp profile). Each is
	// exact: one name, one image, the networks and addresses listed, the
	// security options listed. Only the policy file can add one; the dashboard
	// shows them but cannot create or change them.
	Exceptions []Exception `yaml:"exceptions,omitempty"`

	ports []portRange
}

// Exception is one container's allowance beyond the envelope.
type Exception struct {
	Name  string `yaml:"name" json:"name"`   // exact container name, no wildcard
	Image string `yaml:"image" json:"image"` // repository, no tag
	// Networks are extra networks this container may join, each with the
	// addresses it may be pinned to (empty = joined with an automatic address).
	Networks map[string][]string `yaml:"networks,omitempty" json:"networks,omitempty"`
	// SecOpts are the security options it may ask for, e.g. seccomp=unconfined.
	SecOpts []string `yaml:"secopts,omitempty" json:"secopts,omitempty"`
}

// ExceptionFor is the exception the policy holds for a container name, if any.
func (p *Policy) ExceptionFor(name string) *Exception { return p.exception(name) }

func (p *Policy) exception(name string) *Exception {
	for i := range p.Exceptions {
		if p.Exceptions[i].Name == name {
			return &p.Exceptions[i]
		}
	}
	return nil
}

// secOptKey makes seccomp=unconfined and seccomp:unconfined the same option.
func secOptKey(o string) string { return strings.Replace(o, ":", "=", 1) }

func (e *Exception) allowsSecOpt(o string) bool {
	for _, x := range e.SecOpts {
		if secOptKey(x) == secOptKey(o) {
			return true
		}
	}
	return false
}

func (e *Exception) allowsAddr(network, addr string) bool {
	for _, a := range e.Networks[network] {
		if a == addr {
			return true
		}
	}
	return false
}

func usableIPv4(str string) bool {
	addr, err := netip.ParseAddr(str)
	return err == nil && addr.Is4() && addr.String() == str && !addr.IsUnspecified() && !addr.IsLoopback() &&
		!addr.IsMulticast() && !addr.IsLinkLocalUnicast() && str != "255.255.255.255"
}

type portRange struct {
	lo, hi int
	proto  string
}

const watchtowerLabel = "com.centurylinklabs.watchtower.enable"

// ModulesImages, as an entry in a policy's images, stands for the repositories
// the bundled modules declare.
const ModulesImages = "@modules"

// Defaults are what a policy that leaves out images or networks gets: the
// repositories the bundled modules declare and the app's games network.
type Defaults struct {
	Images  []string
	Network string
	// ModulePorts are the published ports each bundled module declares
	// ("25565/tcp"), by module id. Allowed is the set of module ids the
	// operator switched on (the allowed file); each one adds its ports to the
	// policy's own. An id that is not a bundled module adds nothing, so what
	// the panel can widen is bounded by what the bundled modules declare.
	ModulePorts map[string][]string
	Allowed     []string
}

// Resolve fills in what the policy left out and expands "@modules". The guard
// and the panel both call it with the same Defaults, so a game the panel says
// fits is a game the guard admits.
func (p *Policy) Resolve(d Defaults) error {
	if len(p.Images) == 0 {
		p.Images = []string{ModulesImages}
	}
	var imgs []string
	for _, e := range p.Images {
		if e != ModulesImages {
			imgs = append(imgs, e)
			continue
		}
		for _, r := range d.Images {
			repo, tag, digest, err := parseRef(r)
			if err != nil || tag != "" || digest != "" {
				return fmt.Errorf("policy: a module declares the image %q, which is not a repository without a tag", r)
			}
			imgs = append(imgs, repo)
		}
	}
	if len(imgs) == 0 {
		return errors.New("policy: no images are allowed: list some, or use @modules once a bundled module declares one")
	}
	p.Images = dedupe(imgs)
	if len(p.Networks) == 0 {
		if d.Network == "" || !identRe.MatchString(d.Network) {
			return errors.New("policy: no networks are allowed: list the games network")
		}
		p.Networks = []string{d.Network}
	}
	for _, id := range d.Allowed {
		for _, s := range d.ModulePorts[id] {
			pr, err := parsePortRange(s)
			if err != nil {
				return fmt.Errorf("policy: module %s declares a bad port: %w", id, err)
			}
			if !slices.Contains(p.Ports, s) {
				p.Ports = append(p.Ports, s)
				p.ports = append(p.ports, pr)
			}
		}
	}
	return nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// LoadPolicy reads and validates a policy file.
func LoadPolicy(file string) (*Policy, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	return ParsePolicy(b)
}

// LoadPolicyWith is LoadPolicy followed by Resolve.
func LoadPolicyWith(file string, d Defaults) (*Policy, error) {
	p, err := LoadPolicy(file)
	if err != nil {
		return nil, err
	}
	if err := p.Resolve(d); err != nil {
		return nil, err
	}
	return p, nil
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
		case img == "*" || img == ModulesImages:
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
	seenEx := map[string]bool{}
	for i := range p.Exceptions {
		e := &p.Exceptions[i]
		if !identRe.MatchString(e.Name) || seenEx[e.Name] {
			return nil, fmt.Errorf("policy: exceptions need a unique, exact container name, not %q", e.Name)
		}
		seenEx[e.Name] = true
		repo, tag, digest, err := parseRef(e.Image)
		if err != nil || tag != "" || digest != "" {
			return nil, fmt.Errorf("policy: exception %s: image must be one repository without a tag or digest, not %q", e.Name, e.Image)
		}
		e.Image = repo
		for n, addrs := range e.Networks {
			if !identRe.MatchString(n) || n == "host" || n == "none" {
				return nil, fmt.Errorf("policy: exception %s: bad network %q", e.Name, n)
			}
			for _, a := range addrs {
				if !usableIPv4(a) {
					return nil, fmt.Errorf("policy: exception %s: %q is not a usable unicast IPv4 address", e.Name, a)
				}
			}
		}
		for _, o := range e.SecOpts {
			if o == "" || strings.ContainsAny(o, " ,") {
				return nil, fmt.Errorf("policy: exception %s: bad security option %q", e.Name, o)
			}
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

// NameAllowed reports whether name is a container the policy lets the panel
// manage, the same test the guard applies to a managed scope.
func (p *Policy) NameAllowed(name string) bool { return len(p.Names) == 0 || matchName(p.Names, name) }

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

// PortAllowed reports whether the policy lets a managed game publish this host port on that address.
func (p *Policy) PortAllowed(hostIP, host, proto string) bool {
	return p.portOK(Port{HostIP: hostIP, HostPort: host, Proto: proto}) == nil
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

// NestedBinds is an error when one of the bind sources a and b is inside the
// other. A container that can write a folder can replace any path below it
// with a symlink (to / for instance), and the engine follows a symlink in a
// bind source when it mounts it, so a bind below another bind is a way out to
// the whole host. Equal paths are fine: a container cannot replace its own
// mount point.
func NestedBinds(a, b string) error {
	switch {
	case strings.HasPrefix(a, b+"/"):
		return fmt.Errorf("bind %s is inside bind %s (a container that writes %s could make it a symlink to anywhere on the host)", a, b, b)
	case strings.HasPrefix(b, a+"/"):
		return fmt.Errorf("bind %s is inside bind %s (a container that writes %s could make it a symlink to anywhere on the host)", b, a, a)
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
	ex := p.exception(s.Name)
	if ex == nil && len(p.Names) > 0 && !matchName(p.Names, s.Name) {
		return fmt.Errorf("container name %s is not in the policy's names", s.Name)
	}
	if ex == nil && len(p.Names) == 0 && s.Labels[OwnerLabel] != "true" {
		return fmt.Errorf("container %s must carry the label %s=true (the policy lists no names, so ownership is what scopes a game)", s.Name, OwnerLabel)
	}
	for img := range s.Images {
		if !matchName(p.Images, img) && (ex == nil || ex.Image != img) {
			return fmt.Errorf("image %s is not in the policy's images", img)
		}
	}
	for i, b := range s.Binds {
		if !strings.HasPrefix(b, p.GamesRoot+"/") {
			return fmt.Errorf("bind %s is not inside games_root %s", b, p.GamesRoot)
		}
		for _, o := range s.Binds[:i] {
			if err := NestedBinds(b, o); err != nil {
				return err
			}
		}
	}
	for n := range s.Networks {
		exNet := false
		if ex != nil {
			_, exNet = ex.Networks[n]
		}
		if !(matchName(p.Networks, n) || exNet) || strings.HasPrefix(n, "container:") || n == "host" {
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
		if k == watchtowerLabel && v == "false" || k == OwnerLabel && v == "true" {
			continue
		}
		if !matchName(p.Labels, k) {
			return fmt.Errorf("label %s is not allowed by the policy", k)
		}
	}
	if len(s.Volumes) > 0 || len(s.CapAdd) > 0 || len(s.Aliases) > 0 {
		return errors.New("managed scopes cannot carry volumes, capabilities or aliases")
	}
	for o := range s.SecOpts {
		if ex == nil || !ex.allowsSecOpt(o) {
			return fmt.Errorf("security option %s is not allowed: the policy has no exception for %s that permits it", o, s.Name)
		}
	}
	for n, addrs := range s.IPv4 {
		for _, a := range addrs {
			if ex == nil {
				return fmt.Errorf("address %s on network %s is not allowed: the policy has no exception for %s that pins it", a, n, s.Name)
			}
			if !ex.allowsAddr(n, a) {
				if allowed := ex.Networks[n]; len(allowed) > 0 {
					return fmt.Errorf("address %s on network %s is not allowed: the policy's exception for %s pins %s to %s", a, n, s.Name, n, strings.Join(allowed, ", "))
				}
				return fmt.Errorf("address %s on network %s is not allowed: the policy's exception for %s does not pin an address on %s", a, n, s.Name, n)
			}
		}
	}
	return nil
}
