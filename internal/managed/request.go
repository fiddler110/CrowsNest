package managed

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerguard"
	"github.com/fiddler110/crowsnest/internal/modules"
	"gopkg.in/yaml.v3"
)

// validate checks a Request and returns the game config it stands for.
func (m *Manager) validate(r Request, existing bool) (config.GameConfig, *modules.Manifest, error) {
	var g config.GameConfig
	if !idRe.MatchString(r.ID) {
		return g, nil, errors.New("id must be 2-31 lowercase letters, digits or dashes, starting with a letter")
	}
	if strings.HasSuffix(r.ID, modules.CleanSuffix) {
		return g, nil, fmt.Errorf("id may not end in %q: that name is the one-shot container that empties a game's data", modules.CleanSuffix)
	}
	if strings.HasSuffix(r.ID, modules.FilesSuffix) {
		return g, nil, fmt.Errorf("id may not end in %q: that name is the one-shot container that edits a stopped game's files", modules.FilesSuffix)
	}
	if strings.HasSuffix(r.ID, modules.RestoreSuffix) {
		return g, nil, fmt.Errorf("id may not end in %q: that name is the one-shot container that restores a backup", modules.RestoreSuffix)
	}
	mf, ok := m.Modules.Manifest(r.Module)
	if !ok {
		return g, nil, fmt.Errorf("module %q is not installed", r.Module)
	}
	if !existing && !r.probe && m.gated(mf.ID) {
		if allowed, _ := m.Allowed(); !slices.Contains(allowed, mf.ID) {
			return g, nil, errors.New(notOnMsg(mf.Name))
		}
	}
	if !existing {
		for _, c := range m.Config.Games {
			if c.ID == r.ID || c.ContainerName == r.ID {
				return g, nil, fmt.Errorf("id %q is already used by a game in config.yaml", r.ID)
			}
		}
		if m.find(r.ID) != nil {
			return g, nil, fmt.Errorf("game %q is already enabled", r.ID)
		}
	}
	known := map[string]modules.Option{}
	for _, o := range mf.Options {
		known[o.Key] = o
	}
	opts := map[string]string{}
	for k, v := range r.Options {
		if o, ok := known[k]; ok && o.Secret {
			return g, nil, fmt.Errorf("option %q is a secret: send it as a secret, not an option", k)
		}
		if _, ok := known[k]; !ok && !reserve[k] {
			return g, nil, fmt.Errorf("module %s has no option %q", mf.ID, k)
		}
		if err := plainValue(k, v); err != nil {
			return g, nil, err
		}
		if k == "tag" && v != "" && !tagRe.MatchString(v) {
			return g, nil, fmt.Errorf("image version %q: use letters, digits, dots, dashes and underscores only (no digest or repository)", v)
		}
		if k == "ram" && v != "" {
			if _, err := modules.SizeBytes("ram", v); err != nil {
				return g, nil, err
			}
		}
		opts[k] = v
	}
	for k, v := range r.Secrets {
		if o, ok := known[k]; !ok || !o.Secret {
			return g, nil, fmt.Errorf("module %s has no secret option %q", mf.ID, k)
		}
		if err := plainValue(k, v); err != nil {
			return g, nil, err
		}
	}
	for _, o := range mf.Options {
		if !o.Required && !o.ManagedRequired {
			continue
		}
		if o.Secret {
			if r.Secrets[o.Key] == "" && !existing {
				return g, nil, fmt.Errorf("option %q is required", o.Key)
			}
		} else if opts[o.Key] == "" && o.Default == "" && o.Derive == "" {
			return g, nil, fmt.Errorf("option %q is required", o.Key)
		}
	}
	if mf.Runtime.Image == "" && opts["image"] == "" {
		return g, nil, fmt.Errorf("module %s has no image of its own: set the image option", mf.ID)
	}
	for _, o := range mf.Options {
		if o.Derive != "" && opts[o.Key] == "" {
			opts[o.Key] = deriveOption(o.Derive, r.ID)
		}
	}
	// A secret option K with a sibling K_env names the variable the module reads: point it at ours.
	for _, o := range mf.Options {
		if o.Secret {
			if _, has := known[o.Key+"_env"]; has && opts[o.Key+"_env"] == "" {
				opts[o.Key+"_env"] = envName(r.ID, o.Key)
			}
		}
	}
	g = config.GameConfig{
		ID: r.ID, ContainerName: r.ID, DisplayName: r.DisplayName, Module: r.Module,
		ConnectAddress: r.ConnectAddress, Options: opts, Backup: m.backupFor(mf, r.ID),
	}
	if g.DisplayName == "" {
		g.DisplayName = mf.Name
	}
	if g.ConnectAddress == "" {
		if rd, err := mf.Render(g, m.Platform); err == nil {
			g.ConnectAddress = connectAddress(mf, opts, rd)
		}
	}
	if rd, err := mf.Render(g, m.Platform); err == nil && !r.probe { // a catalogue probe asks about the policy, not the ports in use
		if clash := m.portClash(g.ID, rd); clash != "" {
			return g, nil, errors.New(clash)
		}
		if err := m.bindClash(g.ID, rd); err != nil {
			return g, nil, err
		}
		if err := m.addrClash(g.ID, rd); err != nil {
			return g, nil, err
		}
	}
	return g, mf, nil
}

func plainValue(k, v string) error {
	if len(v) > 512 || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("option %q: values are at most 512 characters with no control characters", k)
	}
	return nil
}

func envName(id, key string) string {
	return strings.ToUpper(strings.ReplaceAll(id, "-", "_") + "_" + key)
}

// connectAddress is what a player types to join: a game on a LAN (macvlan)
// network is reached at its own LAN address; any other game at the address its
// first port is published on, with that port. An address typed into the form
// wins over this (someone who reaches the game by a DNS name or a Tailscale
// address says so there). It is "" when nothing is certain, as when the game is
// published on every address.
func connectAddress(mf *modules.Manifest, opts map[string]string, rd *modules.Rendered) string {
	for _, n := range mf.Runtime.Networks {
		if n.IPv4Option != "" && opts[n.IPv4Option] != "" {
			return opts[n.IPv4Option]
		}
	}
	if rd == nil || len(rd.Scope.Ports) == 0 {
		return ""
	}
	p := rd.Scope.Ports[0]
	if p.HostIP == "" || p.HostIP == "0.0.0.0" {
		return ""
	}
	return net.JoinHostPort(p.HostIP, p.HostPort)
}

// withCopy resolves CopyFrom: secrets the request does not carry come from the named game, which must run the
// same module (a secret means something only to the module that declared it). The result has no CopyFrom, so
// it is never saved. Call with m.mu held.
func (m *Manager) withCopy(r Request) (Request, error) {
	if r.CopyFrom == "" {
		return r, nil
	}
	src := m.find(r.CopyFrom)
	if src == nil {
		return r, fmt.Errorf("there is no game %q to copy settings from", r.CopyFrom)
	}
	if src.Module != r.Module {
		return r, fmt.Errorf("%q runs module %s, not %s: settings can only be copied between games of one module", src.ID, src.Module, r.Module)
	}
	secrets := make(map[string]string, len(src.Secrets)+len(r.Secrets))
	for k, v := range src.Secrets {
		secrets[k] = v
	}
	for k, v := range r.Secrets {
		if v != "" {
			secrets[k] = v
		}
	}
	r.Secrets, r.CopyFrom = secrets, ""
	return r, nil
}

// withDefaults gives a new game its own data folder, named after its id, directly under games_root (which
// the operator points at a folder that holds only game data). Two games from one module must never share a
// folder (they would write the same world). A folder typed in the form is kept.
func (m *Manager) withDefaults(r Request) Request {
	if _, ok := m.Modules.Manifest(r.Module); !ok || r.ID == "" {
		return r
	}
	opts := make(map[string]string, len(r.Options)+2)
	for k, v := range r.Options {
		opts[k] = v
	}
	if spec := m.freePorts(r); spec != "" {
		opts["ports"] = spec
	}
	if opts["data_dir"] == "" {
		opts["data_dir"] = r.ID
	}
	r.Options = opts
	return r
}

// freePorts picks host ports for a game that did not choose any, when the
// module's own are taken by another dashboard game: each is moved up to the
// next free one the policy admits (a second Palworld gets 8212, a third 8213).
// It returns "" when the defaults are free or nothing workable is left, and
// the clash check then says what is wrong.
func (m *Manager) freePorts(r Request) string {
	mf, ok := m.Modules.Manifest(r.Module)
	if !ok || r.Options["ports"] != "" || len(mf.Runtime.Ports) == 0 {
		return ""
	}
	pol, err := m.policy()
	if err != nil {
		return ""
	}
	used := map[string]bool{}
	for _, o := range m.entries {
		if o.ID == r.ID || o.rendered == nil {
			continue
		}
		for _, p := range o.rendered.Scope.Ports {
			used[p.HostPort+"/"+p.Proto] = true
		}
	}
	hostIP := m.Platform.HostIP
	if hostIP == "" {
		hostIP = "0.0.0.0"
	}
	var spec []string
	moved := false
	for _, pt := range mf.Runtime.Ports {
		proto := pt.Proto
		if proto == "" {
			proto = "udp"
		}
		h := pt.Port
		for used[fmt.Sprintf("%d/%s", h, proto)] {
			h++
		}
		if h != pt.Port {
			moved = true
			if h > 65535 || !pol.PortAllowed(hostIP, strconv.Itoa(h), proto) {
				return ""
			}
		}
		used[fmt.Sprintf("%d/%s", h, proto)] = true
		spec = append(spec, fmt.Sprintf("%d:%d/%s", h, pt.Port, proto))
	}
	if !moved {
		return ""
	}
	return strings.Join(spec, ",")
}

// portClash reports a published host port that another dashboard game already uses.
func (m *Manager) portClash(id string, rd *modules.Rendered) string {
	for _, o := range m.entries {
		if o.ID == id || o.rendered == nil {
			continue
		}
		for _, a := range rd.Scope.Ports {
			for _, b := range o.rendered.Scope.Ports {
				if a.HostPort == b.HostPort && a.Proto == b.Proto && (a.HostIP == b.HostIP || a.HostIP == "0.0.0.0" || b.HostIP == "0.0.0.0") {
					return fmt.Sprintf("host port %s/%s is already used by %s: set different ports under More settings", a.HostPort, a.Proto, o.ID)
				}
			}
		}
	}
	return ""
}

// addrClash refuses a fixed address (a macvlan LAN address, or one on the games network) that another dashboard
// game already holds on the same network: two containers cannot own one address.
func (m *Manager) addrClash(id string, rd *modules.Rendered) error {
	for _, o := range m.entries {
		if o.ID == id || o.rendered == nil {
			continue
		}
		for net, mine := range rd.Scope.IPv4 {
			for _, a := range mine {
				if slices.Contains(o.rendered.Scope.IPv4[net], a) {
					return fmt.Errorf("address %s on network %s is already used by %s: choose another address", a, net, o.ID)
				}
			}
		}
	}
	return nil
}

// bindClash refuses a data folder inside another dashboard game's, or holding one: the guard does not load such a
// scope (dockerguard.NestedBinds says why), so it is better refused here, with the game named.
func (m *Manager) bindClash(id string, rd *modules.Rendered) error {
	for _, o := range m.entries {
		if o.ID == id || o.rendered == nil {
			continue
		}
		for _, a := range rd.Scope.Binds {
			for _, b := range o.rendered.Scope.Binds {
				if err := dockerguard.NestedBinds(a, b); err != nil {
					return fmt.Errorf("%w; %s uses that folder: choose another data folder under More settings", err, o.ID)
				}
			}
		}
	}
	return nil
}

// renderAndFit renders the game and checks it against the policy.
func (m *Manager) renderAndFit(g config.GameConfig, mf *modules.Manifest) (*modules.Rendered, error) {
	r, err := mf.Render(g, m.Platform)
	if err != nil {
		return nil, err
	}
	pol, err := m.policy()
	if err != nil {
		return r, err
	}
	js, err := modules.ScopesJSON([]*modules.Rendered{r})
	if err != nil {
		return r, err
	}
	sc, err := dockerguard.LoadScopes(string(js))
	if err != nil {
		return r, err
	}
	return r, pol.Admit(sc[0])
}

// Preview renders a Request without changing anything.
func (m *Manager) Preview(r Request) (*Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.withCopy(r)
	if err != nil {
		return nil, err
	}
	r = m.withDefaults(r)
	g, mf, err := m.validate(r, false)
	if err != nil {
		return nil, err
	}
	rd, fitErr := m.renderAndFit(g, mf)
	if rd == nil {
		return nil, fitErr
	}
	svc, _ := yaml.Marshal(map[string]any{r.ID: rd.Service})
	sc, _ := json.MarshalIndent(rd.Scope, "", "  ")
	p := &Plan{Service: string(svc), Scope: string(sc), Fits: fitErr == nil, Connect: g.ConnectAddress,
		Container: rd.Service.ContainerName, Image: rd.Service.Image, Ports: rd.Service.Ports, Memory: rd.Service.MemLimit,
		Pinning: "Pinned: the container runs the exact image " + rd.Ref() + " points to when it is installed, by digest. Update image moves it on; Roll back returns to the one before."}
	for _, v := range rd.Service.Volumes {
		p.Folders = append(p.Folders, strings.SplitN(v, ":", 2)[0])
	}
	if fitErr != nil {
		p.Reason = fitErr.Error()
	}
	for _, v := range rd.EnvVars {
		p.Env = append(p.Env, v.Name)
	}
	p.Setup = m.setupSteps(r, mf, rd, p.Fits)
	return p, nil
}

var setupRef = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)

// setupSteps is the host-side checklist for this game: the policy exception it needs (written out, ready to
// paste), then the module's own steps with the form's values filled in.
func (m *Manager) setupSteps(r Request, mf *modules.Manifest, rd *modules.Rendered, fits bool) []SetupStep {
	var steps []SetupStep
	sc := rd.Scope
	if len(sc.SecOpts) > 0 || len(sc.IPv4) > 0 || len(sc.Networks) > 1 {
		primary := ""
		if len(sc.Networks) > 0 {
			primary = sc.Networks[0]
		}
		ex := dockerguard.Exception{Name: sc.Name, Networks: map[string][]string{}}
		if len(sc.Images) > 0 {
			ex.Image = sc.Images[0]
		}
		for _, n := range sc.Networks {
			if n != primary || len(sc.IPv4[n]) > 0 {
				ex.Networks[n] = append([]string{}, sc.IPv4[n]...)
			}
		}
		for _, o := range sc.SecOpts {
			if strings.Contains(o, "=") {
				ex.SecOpts = append(ex.SecOpts, o)
			}
		}
		if len(ex.Networks) == 0 {
			ex.Networks = nil
		}
		b, _ := yaml.Marshal(map[string]any{"exceptions": []dockerguard.Exception{ex}})
		done := fits
		detail := "This game needs more than the dashboard may ever grant (a LAN address, a pinned address or a relaxed security profile). Add this block to policy.yaml on the host. The guard picks it up within a few seconds; no restart is needed."
		if m.PolicyFile != "" {
			detail += " The file is " + m.PolicyFile + " inside the panel, which is the policy folder on the host."
		}
		if fits {
			detail = "The policy already has an exception that covers this game exactly as set up here."
		}
		steps = append(steps, SetupStep{Title: "Allow it in policy.yaml", Detail: detail, Command: strings.TrimRight(string(b), "\n"), Done: &done})
	}
	fill := func(t string) string {
		return setupRef.ReplaceAllStringFunc(t, func(ref string) string {
			k := ref[1 : len(ref)-1]
			if k == "id" {
				return r.ID
			}
			known := false
			for _, o := range mf.Options {
				known = known || o.Key == k
			}
			if !known {
				return ref // not ours (a Go template in a docker command, say)
			}
			if v := strings.TrimSpace(r.Options[k]); v != "" {
				return v
			}
			for _, o := range mf.Options {
				if o.Key == k && o.Default != "" {
					return o.Default
				}
			}
			return "<" + k + ">"
		})
	}
	for _, h := range mf.HostSetup {
		steps = append(steps, SetupStep{Title: fill(h.Title), Detail: fill(h.Detail), Command: fill(h.Command)})
	}
	return steps
}
