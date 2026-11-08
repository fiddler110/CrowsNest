package dockerguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Port is a published port a scope may ask for. ContainerPort "" means any.
type Port struct {
	HostIP, HostPort, ContainerPort, Proto string
}

// Scope is one container a client may manage, and everything its create may
// ask for. Nothing loosening is ever a default: host networking,
// seccomp=unconfined or exec must be written into that scope's entry.
type Scope struct {
	Name     string
	Images   map[string]bool // fully qualified repositories, no tag or digest
	Binds    []string        // exact host paths
	Volumes  []string        // named-volume prefixes
	Networks map[string]bool
	Ports    []Port
	Exec     bool
	SecOpts  map[string]bool
	CapAdd   map[string]bool
	Labels   map[string]string
	Aliases  map[string]bool
}

var (
	scopeNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]+$`)
	identRe     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	portRe      = regexp.MustCompile(`^[1-9][0-9]{0,4}(-[1-9][0-9]{0,4})?$`)
	capRe       = regexp.MustCompile(`^[A-Z_]+$`)
	scopeKeys   = map[string]bool{"name": true, "images": true, "binds": true, "volumes": true, "networks": true, "ports": true,
		"exec": true, "secopts": true, "cap_add": true, "labels": true, "aliases": true}
)

// LoadScopes parses GUARD_SCOPES: a non-empty JSON list of scope objects. The
// guard refuses to start on anything it does not understand.
func LoadScopes(raw string) ([]*Scope, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("the guard needs GUARD_SCOPES")
	}
	doc, err := strictJSON([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("GUARD_SCOPES is not valid JSON: %w", err)
	}
	entries, ok := doc.([]any)
	if !ok || len(entries) == 0 {
		return nil, errors.New("GUARD_SCOPES must be a non-empty JSON list of scopes")
	}
	var out []*Scope
	seen := map[string]bool{}
	for i, e := range entries {
		s, err := newScope(e, fmt.Sprintf("scope #%d", i+1))
		if err != nil {
			return nil, err
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("scope %s is listed twice", s.Name)
		}
		seen[s.Name] = true
		out = append(out, s)
	}
	return out, nil
}

func newScope(e any, where string) (*Scope, error) {
	entry, ok := e.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", where)
	}
	var unknown []string
	for k := range entry {
		if !scopeKeys[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("%s: unknown key %q", where, unknown[0])
	}
	s := &Scope{Images: map[string]bool{}, Networks: map[string]bool{}, SecOpts: map[string]bool{}, CapAdd: map[string]bool{},
		Labels: map[string]string{}, Aliases: map[string]bool{}}
	name, _ := entry["name"].(string)
	if !scopeNameRe.MatchString(name) {
		return nil, fmt.Errorf("%s: name must be a container name", where)
	}
	s.Name = name
	where = "scope " + name

	images, err := listOf(entry, "images", where, true)
	if err != nil {
		return nil, err
	}
	for _, ref := range images {
		str, _ := ref.(string)
		repo, tag, digest, perr := parseRef(str)
		if perr != nil || tag != "" || digest != "" {
			return nil, fmt.Errorf("%s: images are repositories without a tag or digest, not %s", where, quote(ref))
		}
		s.Images[repo] = true
	}
	binds, err := listOf(entry, "binds", where, false)
	if err != nil {
		return nil, err
	}
	for _, b := range binds {
		if _, isObj := b.(map[string]any); isObj {
			// A path below an allowed directory may be a symlink the container itself planted (anywhere on the
			// host), and the engine follows it when it binds; so only exact, operator-listed paths are bindable.
			return nil, fmt.Errorf("%s: subpaths are not supported: list each exact bind path as a string, not %s", where, quote(b))
		}
		str, _ := b.(string)
		if !strings.HasPrefix(str, "/") || path.Clean(str) != str || str == "/" || strings.ContainsFunc(str, badBindRune) {
			return nil, fmt.Errorf("%s: a bind is an absolute, normalised path other than /, not %s", where, quote(b))
		}
		s.Binds = append(s.Binds, str)
	}
	volumes, err := listOf(entry, "volumes", where, false)
	if err != nil {
		return nil, err
	}
	for _, p := range volumes {
		str, _ := p.(string)
		if !identRe.MatchString(str) {
			return nil, fmt.Errorf("%s: bad volume prefix %s", where, quote(p))
		}
		s.Volumes = append(s.Volumes, str)
	}
	networks, err := listOf(entry, "networks", where, false)
	if err != nil {
		return nil, err
	}
	for _, n := range networks {
		str, _ := n.(string)
		if !identRe.MatchString(str) {
			return nil, fmt.Errorf("%s: bad network %s (container:<x> is never allowed)", where, quote(n))
		}
		s.Networks[str] = true
	}
	ports, err := listOf(entry, "ports", where, false)
	if err != nil {
		return nil, err
	}
	for _, p := range ports {
		port, err := newPort(p, where)
		if err != nil {
			return nil, err
		}
		s.Ports = append(s.Ports, port)
	}
	if v, present := entry["exec"]; present {
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("%s: exec must be true or false", where)
		}
		s.Exec = b
	}
	secopts, err := listOf(entry, "secopts", where, false)
	if err != nil {
		return nil, err
	}
	for _, o := range secopts {
		str, _ := o.(string)
		if str == "" {
			return nil, fmt.Errorf("%s: bad security option %s", where, quote(o))
		}
		s.SecOpts[str] = true
	}
	caps, err := listOf(entry, "cap_add", where, false)
	if err != nil {
		return nil, err
	}
	for _, c := range caps {
		norm := normCap(c)
		if norm == "" || norm == "ALL" {
			return nil, fmt.Errorf("%s: bad capability %s", where, quote(c))
		}
		s.CapAdd[norm] = true
	}
	if v, present := entry["labels"]; present {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: labels must be an object of exact label: value strings", where)
		}
		for k, lv := range m {
			str, isStr := lv.(string)
			if k == "" || !isStr {
				return nil, fmt.Errorf("%s: labels must be an object of exact label: value strings", where)
			}
			s.Labels[k] = str
		}
	}
	aliases, err := listOf(entry, "aliases", where, false)
	if err != nil {
		return nil, err
	}
	for _, a := range aliases {
		str, _ := a.(string)
		if !identRe.MatchString(str) {
			return nil, fmt.Errorf("%s: bad network alias %s", where, quote(a))
		}
		s.Aliases[str] = true
	}
	return s, nil
}

func badBindRune(r rune) bool {
	return r == ':' || r == ',' || r == 0 || unicode.IsSpace(r) || unicode.IsControl(r)
}

func listOf(entry map[string]any, key, where string, required bool) ([]any, error) {
	v, present := entry[key]
	if !present {
		if required {
			return nil, fmt.Errorf("%s: %s must be a non-empty list", where, key)
		}
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok || (required && len(list) == 0) {
		what := "list"
		if required {
			what = "non-empty list"
		}
		return nil, fmt.Errorf("%s: %s must be a %s", where, key, what)
	}
	return list, nil
}

func newPort(p any, where string) (Port, error) {
	m, ok := p.(map[string]any)
	if ok {
		for k := range m {
			if k != "host_ip" && k != "host_port" && k != "container_port" && k != "proto" {
				ok = false
			}
		}
		_, hasIP := m["host_ip"]
		_, hasPort := m["host_port"]
		ok = ok && hasIP && hasPort
	}
	if !ok {
		return Port{}, fmt.Errorf("%s: a port is {host_ip, host_port, [container_port], [proto]}, not %s", where, quote(p))
	}
	ipStr, _ := m["host_ip"].(string)
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || addr.Zone() != "" {
		return Port{}, fmt.Errorf("%s: bad host_ip %s (use 0.0.0.0 for all interfaces)", where, quote(m["host_ip"]))
	}
	out := Port{HostIP: addr.String(), Proto: "tcp"}
	if pv, present := m["proto"]; present {
		str, _ := pv.(string)
		if str != "tcp" && str != "udp" && str != "sctp" {
			return Port{}, fmt.Errorf("%s: bad proto %s", where, quote(pv))
		}
		out.Proto = str
	}
	for _, key := range []string{"host_port", "container_port"} {
		v, present := m[key]
		if !present {
			continue
		}
		var str string
		switch t := v.(type) {
		case string:
			str = t
		case json.Number:
			if _, isInt := asInt(t); isInt {
				str = string(t)
			}
		}
		if !portRe.MatchString(str) || !portsInRange(str) {
			return Port{}, fmt.Errorf("%s: bad %s %s", where, key, quote(v))
		}
		if key == "host_port" {
			out.HostPort = str
		} else {
			out.ContainerPort = str
		}
	}
	return out, nil
}

func portsInRange(s string) bool {
	for _, p := range strings.Split(s, "-") {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		if n > 65535 {
			return false
		}
	}
	return true
}

// normCap is a capability name as the engine writes it ("NET_ADMIN"), or ""
// when v is not one.
func normCap(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "CAP_")
	if !capRe.MatchString(s) {
		return ""
	}
	return s
}

func (s *Scope) bridgeOK() bool { return s.Networks["bridge"] || s.Networks["default"] }

func (s *Scope) networkOK(name string) bool {
	if name == "" || name == "default" || name == "bridge" {
		return s.bridgeOK()
	}
	return s.Networks[name]
}

func (s *Scope) bindOK(src string) bool {
	for _, b := range s.Binds {
		if b == src {
			return true
		}
	}
	return false
}

func (s *Scope) volumeOK(name string) bool {
	for _, p := range s.Volumes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
