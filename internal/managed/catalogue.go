package managed

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/fiddler110/crowsnest/internal/dockerguard"
	"github.com/fiddler110/crowsnest/internal/modules"
)

type ModuleInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	NeedsImage  bool   `json:"needs_image"` // the module has no image of its own
	Description string `json:"description,omitempty"`
	Image       string `json:"image,omitempty"`
	// DefaultTag is the tag a game follows unless told otherwise; StableTag is
	// the image's stable-release tag, when the module knows one.
	DefaultTag string   `json:"default_tag,omitempty"`
	StableTag  string   `json:"stable_tag,omitempty"`
	Ports      []string `json:"ports,omitempty"` // "25565/tcp"
	// PortNotes says what each published port is for, as the module declares it.
	PortNotes []PortNote `json:"port_notes,omitempty"`
	// Allowed is whether the operator switched this module on. Bundled is whether
	// the guard knows its ports (so a switch can allow them); a module installed
	// from a URL has no switch, its ports go in policy.yaml.
	Allowed bool `json:"allowed"`
	Bundled bool `json:"bundled"`
	// Gated: the switch only lets the dashboard offer the module; its image and
	// ports still have to be in policy.yaml. PolicyLines are those lines, ready to paste.
	Gated       bool   `json:"gated,omitempty"`
	Signed      bool   `json:"signed,omitempty"` // installed from a URL and signed by a key in policy.yaml trusted_keys
	PolicyLines string `json:"policy_lines,omitempty"`
	HasBackup   bool   `json:"has_backup,omitempty"`
	// ConnectHint is the address players most likely use (published host address
	// and first port), offered as the default connect address.
	ConnectHint string `json:"connect_hint,omitempty"`
	// Fits is whether a game from this module, with its defaults and the module's
	// own id, is inside the operator's policy. Nil when it cannot be told (the
	// module needs an image, or a game with that id already exists).
	Fits *bool `json:"fits,omitempty"`
	// FitID is an id the policy's names admit, when the module's own id is not one:
	// the verdict above was reached with it.
	FitID string `json:"fit_id,omitempty"`
	// NeedsException is true for a module that asks for more than the envelope
	// ever grants by itself (a LAN address, a pinned IPv4, a relaxed seccomp
	// profile): it only fits when policy.yaml carries an exception for its id.
	NeedsException bool         `json:"needs_exception,omitempty"`
	Reason         string       `json:"reason,omitempty"`
	Options        []OptionInfo `json:"options"`
}

// OptionInfo and ModuleInfo describe the catalogue to the dashboard.
type OptionInfo struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Default  string `json:"default,omitempty"`
	Required bool   `json:"required,omitempty"`
	Secret   bool   `json:"secret,omitempty"`
	Auto     bool   `json:"auto,omitempty"` // filled in from the game itself when left empty
}

// PortNote is one published port and the module's reason for it.
type PortNote struct {
	Port string `json:"port"` // "25565/tcp"
	Why  string `json:"why,omitempty"`
}

// Catalogue lists the modules that can be enabled from the dashboard: those
// that describe a container (a runtime section).
func (m *Manager) Catalogue() []ModuleInfo {
	var out []ModuleInfo
	defs := modules.PolicyDefaults(m.Platform)
	allowed, _ := dockerguard.ReadAllowed(m.path(allowedFile))
	for _, mf := range m.Modules.Manifests() {
		if len(mf.Runtime.Ports) == 0 && mf.Runtime.Image == "" && len(mf.Runtime.Data) == 0 {
			continue
		}
		rt := mf.Runtime
		mi := ModuleInfo{ID: mf.ID, Name: mf.Name, NeedsImage: mf.Runtime.Image == "",
			NeedsException: len(rt.SecOpts) > 0 || len(rt.Networks) > 0 || rt.GamesIPv4Option != "",
			Description:    mf.Description, Image: mf.Runtime.Image, HasBackup: mf.Backup != nil,
			DefaultTag: cmp.Or(rt.Tag, "latest"), StableTag: rt.StableTag}
		for _, p := range mf.Runtime.Ports {
			mi.Ports = append(mi.Ports, modules.PortSpec(p))
			mi.PortNotes = append(mi.PortNotes, PortNote{Port: modules.PortSpec(p), Why: p.Why})
		}
		mi.Bundled = len(defs.ModulePorts[mf.ID]) > 0
		mi.Allowed = slices.Contains(allowed, mf.ID)
		if m.gated(mf.ID) {
			mi.Gated = true
			mi.PolicyLines = policyLines(mf)
		} else if len(mf.Runtime.Ports) > 0 {
			mi.Bundled = true // not compiled in, but signed by a key the policy trusts: the guard vouches for it the same way
			mi.Signed = !slices.Contains(modules.Bundled().IDs(), mf.ID)
		}
		if len(mf.Runtime.Ports) > 0 && m.Platform.HostIP != "" && m.Platform.HostIP != "0.0.0.0" {
			mi.ConnectHint = fmt.Sprintf("%s:%d", m.Platform.HostIP, mf.Runtime.Ports[0].Port)
		}
		for _, o := range mf.Options {
			mi.Options = append(mi.Options, OptionInfo{Key: o.Key, Label: o.Label, Default: o.Default, Required: (o.Required || o.ManagedRequired) && o.Derive == "", Secret: o.Secret, Auto: o.Derive != ""})
		}
		if mi.Gated && !mi.Allowed {
			no := false
			mi.Fits, mi.Reason = &no, notOnMsg(mf.Name)
		} else {
			m.probeFit(&mi, mf)
		}
		out = append(out, mi)
	}
	return out
}

func notOnMsg(name string) string {
	return name + " is installed but not switched on yet. Switch it on below (your password is asked)."
}

// policyLines is what policy.yaml needs for a module the guard cannot read the needs of itself.
func policyLines(mf *modules.Manifest) string {
	var b strings.Builder
	if mf.Runtime.Image != "" {
		fmt.Fprintf(&b, "images: [\"@modules\", %q]\n", mf.Runtime.Image)
	}
	var ports []string
	for _, p := range mf.Runtime.Ports {
		ports = append(ports, strconv.Quote(modules.PortSpec(p)))
	}
	if len(ports) > 0 {
		fmt.Fprintf(&b, "ports: [%s]\n", strings.Join(ports, ", "))
	}
	return b.String()
}

// probeFit dry-runs the module with its defaults (placeholders for what has
// none) under its own id, to tell the catalogue whether the policy admits it.
func (m *Manager) probeFit(mi *ModuleInfo, mf *modules.Manifest) {
	if mi.NeedsImage {
		return
	}
	if mi.NeedsException {
		pol, err := m.policy()
		if err == nil && pol.ExceptionFor(mf.ID) == nil {
			fits := false
			mi.Fits = &fits
			mi.Reason = fmt.Sprintf("needs an exception in policy.yaml for a container named %s (a LAN address and a relaxed security profile). The dashboard cannot grant it.", mf.ID)
			return
		}
	}
	req := Request{ID: mf.ID, Module: mf.ID, Options: map[string]string{}, Secrets: map[string]string{}, probe: true}
	for _, o := range mf.Options {
		switch {
		case o.Secret:
			req.Secrets[o.Key] = "placeholder"
		case o.Default != "":
			req.Options[o.Key] = o.Default
		case o.Required:
			req.Options[o.Key] = "placeholder"
		}
	}
	plan, err := m.Preview(req)
	if err != nil {
		return
	}
	if !plan.Fits && strings.Contains(plan.Reason, "policy's names") {
		// The module's own id is not an allowed name. Judge the image and ports with one that is.
		if pol, perr := m.policy(); perr == nil {
			for _, n := range pol.Names {
				id := strings.TrimSuffix(n, "*")
				if id == n {
					continue // an exact name is only for that one game
				}
				id += mf.ID
				if !idRe.MatchString(id) {
					continue
				}
				req.ID = id
				if p2, e2 := m.Preview(req); e2 == nil && (p2.Fits || !strings.Contains(p2.Reason, "policy's names")) {
					plan, mi.FitID = p2, id
					break
				}
			}
		}
	}
	fits := plan.Fits
	mi.Fits, mi.Reason = &fits, plan.Reason
}

var deriveEnvRe = regexp.MustCompile(`\{env:([a-z0-9_]+)\}`)

// deriveOption expands an option's derive template for the game id.
func deriveOption(tmpl, id string) string {
	out := deriveEnvRe.ReplaceAllStringFunc(tmpl, func(ref string) string {
		return envName(id, deriveEnvRe.FindStringSubmatch(ref)[1])
	})
	return strings.ReplaceAll(out, "{id}", id)
}
