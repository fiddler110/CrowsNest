// Package managed lets the dashboard enable, configure and remove game servers
// from the module catalogue, inside the operator's policy envelope.
//
// An enabled game is rendered from its module (the same render that backs
// `crowsnest render`), checked against the operator's policy.yaml, written into
// the managed scopes file the guard watches, and then created through the
// guard. The guard enforces the policy itself on what it loads, so this
// package's check is the friendly early answer, not the security boundary.
//
// State lives in one directory the panel can write and the operator's policy
// cannot be reached from: games.json (what is enabled), secrets.json (mode
// 0600, secret option values, never written to a rendered file) and
// scopes.json (read by the guard).
package managed

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fiddler110/crowsnest/internal/vault"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/backup"
	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/dockerguard"
	"github.com/fiddler110/crowsnest/internal/execguard"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/modules"
	"gopkg.in/yaml.v3"
)

// Docker is the part of the engine client the manager uses.
type Docker interface {
	Create(ctx context.Context, s dockerctl.CreateSpec) error
	Pull(ctx context.Context, image string) error
	Remove(ctx context.Context, name string) error
	Exists(ctx context.Context, name string) (bool, error)
	Running(ctx context.Context, name string) (bool, error)
	// ImageDigests is a local image's RepoDigests ("repo@sha256:...").
	ImageDigests(ctx context.Context, image string) ([]string, error)
}

// Manager owns the dashboard-enabled games.
type Manager struct {
	Dir string // state directory
	// Vault encrypts secrets.json; nil leaves values as they are (tests).
	Vault      *vault.Vault
	PolicyFile string // operator's policy.yaml
	// PolicyEditable lets SetPolicy rewrite PolicyFile (the operator mounted it writable and opted in).
	PolicyEditable bool
	Platform       modules.Platform
	// Backups is the panel's view of the shared backups folder; each game's
	// folder is created in it before the container is. Needed when
	// Platform.BackupsRoot is set.
	Backups  *backup.Root
	Modules  *modules.Set
	Config   *config.Config
	Docker   Docker
	Wire     *dockerctl.Client // for module wiring (status, logs, exec)
	Registry *games.Registry
	// Settle is how long a new game waits for the guard to pick up its scope.
	Settle time.Duration
	// Busy, when set, reports a game that is mid start/stop. A start still
	// pulling has no container yet, so Docker.Running alone would miss it.
	Busy func(id string) bool
	// RunHelper runs a one-shot container to completion (the data cleaner);
	// needed only for Disable with DisableOptions.Data.
	RunHelper func(ctx context.Context, spec dockerctl.CreateSpec) error

	mu      sync.Mutex
	ctx     context.Context
	entries []*entry
}

type entry struct {
	Request
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	pin

	rendered *modules.Rendered
	stop     context.CancelFunc
	refresh  string // outcome of the last image update: RefreshUpdated or RefreshUpToDate
}

// pin is the exact image a game runs. A game is pulled by tag, and the digest
// that tag resolved to is what its container is created from, so an upstream
// push changes nothing until the operator presses Update image. The digest
// before the last change is kept for a rollback.
type pin struct {
	Image          string `json:"image,omitempty"` // repo:tag the digest was resolved from
	Digest         string `json:"digest,omitempty"`
	PreviousDigest string `json:"previous_digest,omitempty"`
}

// Outcomes of an image update, as Info.Refresh reports them.
const (
	RefreshUpdated  = "updated"
	RefreshUpToDate = "up_to_date"
)

// ErrNoPrevious is a rollback with nothing to go back to.
var ErrNoPrevious = errors.New("there is no previous image to roll back to")

// Request is what the dashboard sends to enable a game.
type Request struct {
	ID             string            `json:"id"`
	Module         string            `json:"module"`
	DisplayName    string            `json:"display_name,omitempty"`
	ConnectAddress string            `json:"connect_address,omitempty"`
	Options        map[string]string `json:"options,omitempty"`
	// Secrets holds the values of the module's secret options. They are kept
	// in secrets.json and never appear in a plan, a rendered file or a list.
	Secrets map[string]string `json:"secrets,omitempty"`

	probe bool // set by the catalogue's fit check: judge the policy only
}

// Info is a managed game as the dashboard lists it.
type Info struct {
	ID     string `json:"id"`
	Module string `json:"module"`
	State  string `json:"state"` // installing, ready, failed
	Error  string `json:"error,omitempty"`
	// What the edit form pre-fills. Secret values are never listed.
	DisplayName    string            `json:"display_name,omitempty"`
	ConnectAddress string            `json:"connect_address,omitempty"` // only what was typed in the form
	Connect        string            `json:"connect,omitempty"`         // what players use: typed, or worked out from the published port
	Options        map[string]string `json:"options,omitempty"`
	// Image is the tag the game follows (repo:tag); Digest is the exact image it
	// runs (empty for a game installed before pinning, until its next update);
	// PreviousDigest is what Rollback goes back to.
	Image          string `json:"image,omitempty"`
	Digest         string `json:"digest,omitempty"`
	PreviousDigest string `json:"previous_digest,omitempty"`
	// Refresh is how the last Update image ended: "updated" or "up_to_date".
	Refresh string `json:"refresh,omitempty"`
}

// Plan is the dry-run of a Request.
type Plan struct {
	Service string   `json:"service"` // the compose service
	Scope   string   `json:"scope"`   // the guard scope
	Env     []string `json:"env"`     // .env variables the service reads
	Fits    bool     `json:"fits"`    // inside the operator's policy
	Reason  string   `json:"reason,omitempty"`
	// The plain-language summary the dashboard shows beside the form.
	Container string   `json:"container,omitempty"`
	Image     string   `json:"image,omitempty"`
	Ports     []string `json:"ports,omitempty"`   // host_ip:port/proto -> container
	Connect   string   `json:"connect,omitempty"` // what players type to join
	Folders   []string `json:"folders,omitempty"` // host folders the game stores data in
	Memory    string   `json:"memory,omitempty"`
	// Pinning says how the image is held still: the tag is resolved to a digest on install.
	Pinning string `json:"pinning,omitempty"`
	// Setup is what the operator has to do on the host for this game, in order.
	Setup []SetupStep `json:"setup,omitempty"`
}

// SetupStep is one host-side step the dashboard cannot do for the operator.
type SetupStep struct {
	Title   string `json:"title"`
	Detail  string `json:"detail,omitempty"`
	Command string `json:"command,omitempty"` // text to copy
	Done    *bool  `json:"done,omitempty"`    // known to be done (nil = cannot be told from here)
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

const (
	StateInstalling = "installing"
	StateReady      = "ready"
	StateFailed     = "failed"
)

var (
	idRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	tagRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	reserve = map[string]bool{"image": true, "tag": true, "ports": true, "data_dir": true, "ram": true}
)

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

// validate checks a Request and returns the game config it stands for.
func (m *Manager) validate(r Request, existing bool) (config.GameConfig, *modules.Manifest, error) {
	var g config.GameConfig
	if !idRe.MatchString(r.ID) {
		return g, nil, errors.New("id must be 2-31 lowercase letters, digits or dashes, starting with a letter")
	}
	if strings.HasSuffix(r.ID, modules.CleanSuffix) {
		return g, nil, fmt.Errorf("id may not end in %q: that name is the one-shot container that empties a game's data", modules.CleanSuffix)
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

// backupFor is the module's backup block for game id. With a shared backups
// folder and a module that names a backup dir, the panel reads that game's own
// folder (<backups_root>/<id>) instead of listing through docker exec.
// RestoreSpec is the one-shot container that restores file into game id, or
// false when the game is not a dashboard game or its module cannot restore.
func (m *Manager) RestoreSpec(id, file string) (dockerctl.CreateSpec, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.ID == id && e.rendered != nil {
			return e.rendered.RestoreSpec(file)
		}
	}
	return dockerctl.CreateSpec{}, false
}

func (m *Manager) backupFor(mf *modules.Manifest, id string) *config.BackupConfig {
	if mf.Backup == nil {
		return nil
	}
	b := *mf.Backup
	if mf.Backup.Dir != "" && m.Platform.BackupsRoot != "" {
		b.LocalDir = m.Platform.BackupLocalDir(id)
	}
	return &b
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

func plainValue(k, v string) error {
	if len(v) > 512 || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("option %q: values are at most 512 characters with no control characters", k)
	}
	return nil
}

func envName(id, key string) string {
	return strings.ToUpper(strings.ReplaceAll(id, "-", "_") + "_" + key)
}

func (m *Manager) find(id string) *entry {
	for _, e := range m.entries {
		if e.ID == id {
			return e
		}
	}
	return nil
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

// policy is the policy in force: the file plus the ports of the modules switched on.
func (m *Manager) policy() (*dockerguard.Policy, error) {
	return m.loadPolicy(true)
}

// filePolicy is what policy.yaml itself says, without the allowed modules' ports.
func (m *Manager) filePolicy() (*dockerguard.Policy, error) {
	return m.loadPolicy(false)
}

func (m *Manager) loadPolicy(withAllowed bool) (*dockerguard.Policy, error) {
	if m.PolicyFile == "" {
		return nil, errors.New("no policy file is configured: managed games need an operator policy")
	}
	d := modules.PolicyDefaults(m.Platform)
	if withAllowed {
		var err error
		if d.Allowed, err = dockerguard.ReadAllowed(m.path(allowedFile)); err != nil {
			return nil, err
		}
	}
	return dockerguard.LoadPolicyWith(m.PolicyFile, d)
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

// Preview renders a Request without changing anything.
func (m *Manager) Preview(r Request) (*Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
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

// Enable records the game and installs it in the background: scope, image,
// container, then it joins the dashboard. It returns once the request is
// accepted; List shows the progress.
func (m *Manager) Enable(r Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r = m.withDefaults(r)
	g, mf, err := m.validate(r, false)
	if err != nil {
		return err
	}
	rd, err := m.renderAndFit(g, mf)
	if err != nil {
		return fmt.Errorf("outside the operator's policy (add it to policy.yaml to allow it): %w", err)
	}
	e := &entry{Request: r, State: StateInstalling, rendered: rd}
	m.entries = append(m.entries, e)
	if err := m.save(); err != nil {
		m.entries = m.entries[:len(m.entries)-1]
		return err
	}
	go m.install(e, g, installMode{})
	return nil
}

// install is idempotent: it can be re-run for a half-installed game.
// installMode says how to (re)install: recreate removes any existing container
// first (its data folder is a bind mount, so nothing is lost); pull makes a
// failed pull fatal (otherwise an unreachable registry is tolerated when the
// image is already local).
type installMode struct{ recreate, pull bool }

func (m *Manager) install(e *entry, g config.GameConfig, mode installMode) {
	err := m.doInstall(e, g, mode)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		log.Printf("managed: installing %s failed: %v", e.ID, err)
		e.State, e.Error = StateFailed, err.Error()
	} else {
		e.State, e.Error = StateReady, ""
	}
	if serr := m.save(); serr != nil {
		log.Printf("managed: saving state: %v", serr)
	}
}

func (m *Manager) doInstall(e *entry, g config.GameConfig, mode installMode) error {
	m.mu.Lock()
	rd := e.rendered
	ref, repo, name := rd.Ref(), rd.Repo, rd.Service.ContainerName
	cur := e.pin
	err := m.writeScopes()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if name == "" {
		name = rd.ID
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	// The panel makes the game's backup folder itself: if Docker created the
	// bind source it would be root-owned, and a missing external drive would
	// look like a fresh empty folder.
	if g.Backup != nil && g.Backup.LocalDir != "" {
		if m.Backups == nil {
			return errors.New("platform.backups_root is set but the panel has no backups folder mounted")
		}
		if err := m.Backups.EnsureGameDir(rd.ID); err != nil {
			return err
		}
	}
	exists, err := m.Docker.Exists(ctx, name)
	if err != nil {
		return err
	}
	if exists && !mode.recreate {
		return m.register(e, g) // a half-finished install whose container is already there
	}
	// A pull tolerated when it fails: an edit or rollback can use the image already on the host.
	tolerant := mode.recreate && !mode.pull
	pull := func(image string) error {
		// The guard reloads on its own schedule; until it has our scope it answers 403.
		err := m.retryDenied(ctx, func() error { return m.Docker.Pull(ctx, image) })
		if err != nil && tolerant && !dockerctl.IsDenied(err) {
			log.Printf("managed: pull %s failed, using the local image: %v", image, err)
			return nil
		}
		if err != nil {
			return fmt.Errorf("pull %s: %w", image, err)
		}
		return nil
	}

	next := cur
	if mode.pull || cur.Digest == "" || cur.Image != ref {
		// Follow the tag: pull it and pin what it resolves to now.
		before := cur.Digest
		if before == "" && exists {
			before, _ = m.digestOf(ctx, ref, repo) // an install from before pinning: what the tag pointed to until now
		}
		if cur.Image != "" && cur.Image != ref && !sameRepo(cur.Image, repo) {
			before = "" // another repository: its digests mean nothing here
		}
		if err := pull(ref); err != nil {
			if exists {
				// The old container was never touched: keep the game on the dashboard as it was.
				if rerr := m.register(e, g); rerr != nil {
					log.Printf("managed: %s: %v", e.ID, rerr)
				}
			}
			return err
		}
		d, derr := m.digestOf(ctx, ref, repo)
		if derr != nil {
			log.Printf("managed: %s: no digest to pin, running the tag: %v", e.ID, derr)
		}
		next = pin{Image: ref, Digest: d, PreviousDigest: cur.PreviousDigest}
		if cur.Image != "" && !sameRepo(cur.Image, repo) {
			next.PreviousDigest = ""
		}
		if before != "" && d != "" && before != d {
			next.PreviousDigest = before
		}
		if mode.pull {
			m.mu.Lock()
			e.refresh = RefreshUpdated
			if d != "" && d == before {
				e.refresh = RefreshUpToDate // the same image (an older install is still recreated once, to pin it)
			}
			if d != "" && d == cur.Digest && exists {
				// Nothing new upstream: the container stays exactly as it is.
				e.refresh = RefreshUpToDate
				m.mu.Unlock()
				return m.register(e, g)
			}
			m.mu.Unlock()
		}
	} else if _, ierr := m.Docker.ImageDigests(ctx, repo+"@"+cur.Digest); ierr != nil {
		// Pinned, but the image is not on the host (pruned): fetch exactly that one.
		if err := pull(repo + "@" + cur.Digest); err != nil {
			return err
		}
	}

	m.mu.Lock()
	e.pin = next
	rd.Pin(next.Digest)
	spec, err := rd.Spec(m.lookup(e))
	if err == nil {
		err = m.save()
	}
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if exists {
		if err := m.Docker.Remove(ctx, name); err != nil {
			return fmt.Errorf("remove the old container: %w", err)
		}
	}
	if err := m.retryDenied(ctx, func() error { return m.Docker.Create(ctx, spec) }); err != nil {
		return fmt.Errorf("create container: %w", err)
	}
	return m.register(e, g)
}

// digestOf is the registry digest (sha256:...) the local image ref carries for repo.
func (m *Manager) digestOf(ctx context.Context, ref, repo string) (string, error) {
	list, err := m.Docker.ImageDigests(ctx, ref)
	if err != nil {
		return "", err
	}
	want, _, _, err := dockerguard.ParseImageRef(repo)
	if err != nil {
		return "", err
	}
	for _, rd := range list {
		name, d, ok := strings.Cut(rd, "@")
		if !ok || !dockerguard.IsDigest(d) {
			continue
		}
		if r, _, _, err := dockerguard.ParseImageRef(name); err == nil && r == want {
			return d, nil
		}
	}
	return "", fmt.Errorf("%s has no registry digest for %s (built locally?)", ref, repo)
}

// sameRepo reports whether the tag reference ref names repository repo.
func sameRepo(ref, repo string) bool {
	a, _, _, err1 := dockerguard.ParseImageRef(ref)
	b, _, _, err2 := dockerguard.ParseImageRef(repo)
	return err1 == nil && err2 == nil && a == b
}

func (m *Manager) retryDenied(ctx context.Context, f func() error) error {
	wait := m.Settle
	if wait == 0 {
		wait = 30 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		err := f()
		if err == nil || !dockerctl.IsDenied(err) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// lookup resolves a compose variable: the game's own secrets, then the panel's environment, but only for the
// variables this game owns (TZ, and <ID>_<OPTION> for its module's options). Anything else is unset: an option
// such as rcon_password_env, or a module's env, must not be able to name another variable of the panel's
// environment (an OAuth client secret, a webhook URL, another game's password) and have it sent to the game.
func (m *Manager) lookup(e *entry) func(string) (string, bool) {
	secrets := m.secretsFor(e)
	own := map[string]bool{"TZ": true}
	if mf, ok := m.Modules.Manifest(e.Module); ok {
		for _, o := range mf.Options {
			own[envName(e.ID, o.Key)] = true
		}
	}
	return func(name string) (string, bool) {
		if v, ok := secrets[name]; ok {
			return v, true
		}
		if !own[name] {
			return "", false
		}
		return os.LookupEnv(name)
	}
}

func (m *Manager) secretsFor(e *entry) map[string]string {
	out := map[string]string{}
	for k, v := range e.Secrets {
		out[envName(e.ID, k)] = v
	}
	return out
}

// register puts the game on the dashboard: its module's probes, runners and registry entry.
func (m *Manager) register(e *entry, g config.GameConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	find := m.lookup(e)
	lookup := func(name string) string {
		v, _ := find(name)
		return v
	}
	def, runners := m.Modules.BuildOne(m.Config, g, m.Wire, lookup)
	if mf, ok := m.Modules.Manifest(e.Module); ok {
		for _, c := range mf.Connect {
			v := e.Secrets[c.Option]
			if v == "" {
				v = e.Options[c.Option]
			}
			if v != "" {
				def.ConnectSecrets = append(def.ConnectSecrets, games.ConnectSecret{Label: c.Label, Value: v})
			}
		}
	}
	if err := m.Registry.Add(def); err != nil {
		if _, have := m.Registry.Get(g.ID); !have {
			return err
		}
		return nil // already registered (re-run)
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	rctx, cancel := context.WithCancel(ctx)
	e.stop = cancel
	for _, r := range runners {
		go r.Run(rctx)
	}
	return nil
}

// Update changes an enabled game's settings and recreates its container with
// them. The module cannot change. Secrets left out keep their stored value.
// The game must be stopped; its data folder is untouched.
func (m *Manager) Update(r Request) error { return m.reinstall(r, opEdit) }

// Refresh pulls the game's image tag again and, only if it now points at
// another image, recreates the container on that digest (the old one becomes
// the rollback target). List reports the outcome in Info.Refresh once done.
func (m *Manager) Refresh(id string) error { return m.reinstall(Request{ID: id}, opRefresh) }

// Rollback recreates a stopped game's container on its previous image digest,
// and makes the current one the previous (so a second rollback undoes it).
// ErrNoPrevious when there is none.
func (m *Manager) Rollback(id string) error { return m.reinstall(Request{ID: id}, opRollback) }

var errBusy = errors.New("the game is starting or stopping; wait for it to finish")

type reinstallOp int

const (
	opEdit reinstallOp = iota
	opRefresh
	opRollback
)

func (m *Manager) reinstall(r Request, op reinstallOp) error {
	refresh := op != opEdit
	if m.Busy != nil && m.Busy(r.ID) {
		return errBusy
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if running, err := m.Docker.Running(ctx, r.ID); err != nil {
		return err
	} else if running {
		return errors.New("stop the game before changing it")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.find(r.ID)
	if e == nil {
		return fmt.Errorf("game %q is not a dashboard-enabled game", r.ID)
	}
	if e.State == StateInstalling {
		return errors.New("the game is still installing")
	}
	if op == opRollback && (e.PreviousDigest == "" || e.Image == "") {
		return ErrNoPrevious
	}
	next := e.Request
	if !refresh {
		if r.Module != "" && r.Module != e.Module {
			return errors.New("a game's module cannot change: disable it and enable it again")
		}
		next.DisplayName, next.ConnectAddress, next.Options = r.DisplayName, r.ConnectAddress, r.Options
		next.Secrets = map[string]string{}
		for k, v := range e.Secrets {
			next.Secrets[k] = v
		}
		for k, v := range r.Secrets {
			if v != "" {
				next.Secrets[k] = v
			}
		}
	}
	g, mf, err := m.validate(next, true)
	if err != nil {
		return err
	}
	rd, err := m.renderAndFit(g, mf)
	if err != nil {
		return fmt.Errorf("outside the operator's policy (add it to policy.yaml to allow it): %w", err)
	}
	if e.stop != nil {
		e.stop()
		e.stop = nil
	}
	m.Registry.Remove(e.ID)
	e.Request, e.rendered, e.State, e.Error, e.refresh = next, rd, StateInstalling, "", ""
	if op == opRollback {
		e.Digest, e.PreviousDigest = e.PreviousDigest, e.Digest
	}
	if err := m.save(); err != nil {
		return err
	}
	go m.install(e, g, installMode{recreate: true, pull: op == opRefresh})
	return nil
}

// DisableOptions says what Disable deletes besides the game itself.
type DisableOptions struct {
	Data    bool // empty the game's data folders (a one-shot <id>-clean container)
	Backups bool // delete the game's folder in the shared backups folder
}

// Disable removes a stopped game: its container, dashboard entry, scope and
// secrets. Its data folders and backups are kept unless o says otherwise;
// when it does, they are deleted first, so a failure leaves the game listed
// and the deletion can be retried.
func (m *Manager) Disable(id string, o DisableOptions) error {
	m.mu.Lock()
	e := m.find(id)
	m.mu.Unlock()
	if e == nil {
		return fmt.Errorf("game %q is not a dashboard-enabled game", id)
	}
	if m.Busy != nil && m.Busy(id) {
		return errBusy
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	running, err := m.Docker.Running(ctx, id)
	if err != nil {
		return err
	}
	if running {
		return errors.New("stop the game before disabling it")
	}
	if o.Backups && (m.Backups == nil || m.Platform.BackupsRoot == "") {
		return errors.New("this panel has no shared backups folder, so there is nothing to delete there")
	}
	var clean dockerctl.CreateSpec
	if o.Data {
		var ok bool
		m.mu.Lock()
		if e.rendered != nil {
			clean, ok = e.rendered.CleanSpec()
		}
		m.mu.Unlock()
		if !ok || m.RunHelper == nil {
			return errors.New("this game has no data folders the panel can empty")
		}
	}
	if o.Backups {
		if err := m.Backups.Verify(); err != nil { // refuse before anything is deleted
			return err
		}
	}
	if o.Data {
		if err := m.RunHelper(ctx, clean); err != nil {
			return fmt.Errorf("emptying the data folders failed (nothing else was changed): %w", err)
		}
	}
	if ok, _ := m.Docker.Exists(ctx, id); ok {
		if err := m.Docker.Remove(ctx, id); err != nil {
			return err
		}
	}
	if o.Backups {
		if err := m.Backups.RemoveGameDir(id); err != nil {
			return fmt.Errorf("deleting the backups failed: %w", err)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.stop != nil {
		e.stop()
	}
	m.Registry.Remove(id)
	for i, x := range m.entries {
		if x == e {
			m.entries = append(m.entries[:i], m.entries[i+1:]...)
			break
		}
	}
	if err := m.writeScopes(); err != nil {
		return err
	}
	return m.save()
}

// List reports every managed game.
func (m *Manager) List() []Info {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Info, 0, len(m.entries))
	for _, e := range m.entries {
		opts := make(map[string]string, len(e.Options))
		for k, v := range e.Options {
			opts[k] = v
		}
		connect := e.ConnectAddress
		if mf, ok := m.Modules.Manifest(e.Module); ok && connect == "" {
			connect = connectAddress(mf, e.Options, e.rendered)
		}
		in := Info{ID: e.ID, Module: e.Module, State: e.State, Error: e.Error,
			DisplayName: e.DisplayName, ConnectAddress: e.ConnectAddress, Connect: connect, Options: opts,
			Image: e.Image, Digest: e.Digest, PreviousDigest: e.PreviousDigest, Refresh: e.refresh}
		if in.Image == "" && e.rendered != nil {
			in.Image = e.rendered.Ref()
		}
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---- persistence

type stateFile struct {
	Games []savedGame `json:"games"`
}

type savedGame struct {
	Request
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	pin
}

func (m *Manager) path(name string) string { return filepath.Join(m.Dir, name) }

// save writes games.json (without secrets) and secrets.json (0600).
func (m *Manager) save() error {
	var st stateFile
	secrets := map[string]map[string]string{}
	for _, e := range m.entries {
		req := e.Request
		req.Secrets = nil
		st.Games = append(st.Games, savedGame{req, e.State, e.Error, e.pin})
		if len(e.Secrets) > 0 {
			secrets[e.ID] = e.Secrets
		}
	}
	if err := writeJSON(m.path("games.json"), st, 0o600); err != nil {
		return err
	}
	sealed, err := m.sealSecrets(secrets)
	if err != nil {
		return err
	}
	return writeJSON(m.path("secrets.json"), sealed, 0o600)
}

func secretPurpose(game, key string) string { return "managed:" + game + ":" + key }

// sealSecrets encrypts every value of secrets (game id, option key, value).
func (m *Manager) sealSecrets(secrets map[string]map[string]string) (map[string]map[string]string, error) {
	out := make(map[string]map[string]string, len(secrets))
	for id, kv := range secrets {
		out[id] = make(map[string]string, len(kv))
		for k, v := range kv {
			enc, err := m.Vault.Seal(secretPurpose(id, k), v)
			if err != nil {
				return nil, err
			}
			out[id][k] = enc
		}
	}
	return out, nil
}

// unsealSecrets decrypts what sealSecrets wrote. legacy says some value was
// still plain text from an older version, so the file should be rewritten.
func (m *Manager) unsealSecrets(secrets map[string]map[string]string) (plain map[string]map[string]string, legacy bool, err error) {
	plain = make(map[string]map[string]string, len(secrets))
	for id, kv := range secrets {
		plain[id] = make(map[string]string, len(kv))
		for k, v := range kv {
			p, old, err := m.Vault.Unseal(secretPurpose(id, k), v)
			if err != nil {
				return nil, false, fmt.Errorf("secrets.json (%s, %s): %w", id, k, err)
			}
			legacy = legacy || old
			plain[id][k] = p
		}
	}
	return plain, legacy, nil
}

func (m *Manager) writeScopes() error {
	rs := make([]*modules.Rendered, 0, len(m.entries))
	for _, e := range m.entries {
		rs = append(rs, e.rendered)
	}
	if len(rs) == 0 {
		return writeAtomic(m.path("scopes.json"), []byte("[]\n"), 0o644)
	}
	b, err := modules.ScopesJSON(rs)
	if err != nil {
		return err
	}
	return writeAtomic(m.path("scopes.json"), append(b, '\n'), 0o644) // the guard reads this; it holds no secrets
}

func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'), mode)
}

// writeAtomic writes via a temp file and rename so a reader (the guard) never sees half a file.
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Restore loads the saved games at start-up and puts them back on the
// dashboard; one that never finished installing is installed again.
func (m *Manager) Restore(ctx context.Context) error {
	m.mu.Lock()
	m.ctx = ctx
	if err := os.MkdirAll(m.Dir, 0o750); err != nil {
		m.mu.Unlock()
		return err
	}
	var st stateFile
	if b, err := os.ReadFile(m.path("games.json")); err == nil {
		if err := json.Unmarshal(b, &st); err != nil {
			m.mu.Unlock()
			return fmt.Errorf("games.json: %w", err)
		}
	}
	secrets := map[string]map[string]string{}
	if b, err := os.ReadFile(m.path("secrets.json")); err == nil {
		if err := json.Unmarshal(b, &secrets); err != nil {
			m.mu.Unlock()
			return fmt.Errorf("secrets.json: %w", err)
		}
	}
	secrets, legacy, uerr := m.unsealSecrets(secrets)
	if uerr != nil {
		m.mu.Unlock()
		return uerr
	}
	if legacy && m.Vault != nil {
		// Written by an older version in plain text: seal it now.
		sealed, err := m.sealSecrets(secrets)
		if err == nil {
			err = writeJSON(m.path("secrets.json"), sealed, 0o600)
		}
		if err != nil {
			log.Printf("warning: could not encrypt %s: %v", m.path("secrets.json"), err)
		} else {
			log.Printf("secrets: encrypted the game secrets in %s", m.path("secrets.json"))
		}
	}
	type todo struct {
		e *entry
		g config.GameConfig
	}
	var installs []todo
	for _, s := range st.Games {
		req := s.Request
		req.Secrets = secrets[req.ID]
		g, mf, err := m.validate(req, true)
		e := &entry{Request: req, State: s.State, Error: s.Error, pin: s.pin}
		if err == nil {
			e.rendered, err = mf.Render(g, m.Platform)
		}
		if err == nil && e.Digest != "" && e.Image == e.rendered.Ref() {
			e.rendered.Pin(e.Digest)
		}
		if err != nil {
			log.Printf("managed: %s no longer renders: %v", req.ID, err)
			e.State, e.Error = StateFailed, err.Error()
			m.entries = append(m.entries, e)
			continue
		}
		m.entries = append(m.entries, e)
		installs = append(installs, todo{e, g})
	}
	// Re-issue the scopes so a game installed before an upgrade gets any scope
	// the new version added (a restore container).
	if len(m.entries) > 0 {
		if err := m.writeScopes(); err != nil {
			log.Printf("managed: rewriting the guard scopes: %v", err)
		}
	}
	m.mu.Unlock()
	for _, t := range installs {
		if t.e.State == StateReady {
			if err := m.register(t.e, t.g); err != nil {
				log.Printf("managed: restoring %s: %v", t.e.ID, err)
			}
			continue
		}
		go m.install(t.e, t.g, installMode{})
	}
	return nil
}

// ExecRules is the exec allowlist for the dashboard-enabled games in dir: for
// each, its module's backup command (and listing) in the container named after
// the game. The commands come from the installed modules, never from the saved
// state, so what the panel writes there can choose a game but not a command.
// It also cannot choose a container the policy keeps out of its reach: a game
// whose id is not a name the policy lets the panel manage gets no rule, so a
// tampered games.json cannot aim a backup command at an unrelated container.
// The policy file is required; unreadable, no rules are issued.
func ExecRules(dir, policyFile string, mods *modules.Set) ([]execguard.Rule, error) {
	return ExecRulesFor(dir, policyFile, mods, false)
}

// ExecRulesFor is ExecRules for a platform that may share a backups folder.
// With sharedBackups, a module that names a backup dir gets no listing or
// pruning command: the panel reads and prunes that folder itself.
func ExecRulesFor(dir, policyFile string, mods *modules.Set, sharedBackups bool) ([]execguard.Rule, error) {
	if policyFile == "" {
		return nil, errors.New("exec rules for dashboard games need managed.policy_file")
	}
	pol, err := dockerguard.LoadPolicy(policyFile) // only names are read here, so nothing is resolved
	if err != nil {
		return nil, fmt.Errorf("exec rules: %w", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "games.json")) // #nosec G304 -- dir is the operator-set managed.dir; the file name is fixed
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st stateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("games.json: %w", err)
	}
	var rules []execguard.Rule
	for _, g := range st.Games {
		mf, ok := mods.Manifest(g.Module)
		if !ok || mf.Backup == nil || !idRe.MatchString(g.ID) || !pol.NameAllowed(g.ID) {
			continue
		}
		rules = append(rules, execguard.Rule{Container: g.ID, Cmd: mf.Backup.Exec})
		if sharedBackups && mf.Backup.Dir != "" {
			continue
		}
		if dir := mf.Backup.ExecListDir(); dir != "" {
			rules = append(rules, execguard.Rule{Container: g.ID, Cmd: backup.ListArgs(dir)})
		}
		if mf.Backup.Keep > 0 {
			rules = append(rules, execguard.Rule{Container: g.ID, Cmd: backup.PruneArgs(mf.Backup.ExecListDir(), mf.Backup.Keep)})
		}
	}
	return rules, nil
}

// PolicyDoc is policy.yaml as the dashboard shows and edits it.
type PolicyDoc struct {
	GamesRoot string `json:"games_root" yaml:"games_root"`
	// BackupsRoot is read-only here, like GamesRoot.
	BackupsRoot string   `json:"backups_root,omitempty" yaml:"backups_root,omitempty"`
	Names       []string `json:"names" yaml:"names"`
	Images      []string `json:"images" yaml:"images"`
	Networks    []string `json:"networks" yaml:"networks"`
	Ports       []string `json:"ports" yaml:"ports"`
	HostIPs     []string `json:"host_ips" yaml:"host_ips,omitempty"`
	Exec        bool     `json:"exec" yaml:"exec"`
	Labels      []string `json:"labels" yaml:"labels,omitempty"`
	MaxScopes   int      `json:"max_scopes" yaml:"max_scopes"`
	// PinDigests: managed creates must name their image by digest. Nil in a save keeps what the file has.
	PinDigests *bool `json:"pin_digests,omitempty" yaml:"pin_digests"`
	// Exceptions are shown, never edited here: SetPolicy keeps whatever the file has.
	Exceptions []dockerguard.Exception `json:"exceptions,omitempty" yaml:"exceptions,omitempty"`
}

// PolicyState is the current policy and whether the dashboard may change it.
type PolicyState struct {
	Policy   PolicyDoc `json:"policy"`
	Editable bool      `json:"editable"`
}

// Policy reads the policy in force.
func (m *Manager) Policy() (PolicyState, error) {
	p, err := m.filePolicy()
	if err != nil {
		return PolicyState{}, err
	}
	return PolicyState{Editable: m.PolicyEditable, Policy: PolicyDoc{
		GamesRoot: p.GamesRoot, BackupsRoot: p.BackupsRoot, Names: p.Names, Images: p.Images, Networks: p.Networks, Ports: p.Ports,
		HostIPs: p.HostIPs, Exec: p.Exec, Labels: p.Labels, MaxScopes: p.MaxScopes, Exceptions: p.Exceptions,
		PinDigests: &p.PinDigests,
	}}, nil
}

// narrowOnly refuses an edit that would let the panel do more than the file
// on the host already allows. A panel that can rewrite its own policy could
// otherwise widen it as far as it likes, so the dashboard may only tighten:
// every list entry must already be in the file (compared exactly, since two
// patterns cannot be compared by what they match), numbers may only fall and
// switches may only turn toward the stricter setting. Widening is done in
// policy.yaml on the host.
func narrowOnly(cur *dockerguard.Policy, d PolicyDoc) error {
	const hint = "the dashboard can only tighten the policy; widen it in policy.yaml on the host"
	subset := func(name string, now, was []string) error {
		for _, e := range now {
			if !slices.Contains(was, e) {
				return fmt.Errorf("%s: %q is not in the current policy (%s)", name, e, hint)
			}
		}
		return nil
	}
	if d.GamesRoot != cur.GamesRoot {
		return fmt.Errorf("games_root cannot be changed here (%s)", hint)
	}
	if d.BackupsRoot != cur.BackupsRoot {
		return fmt.Errorf("backups_root cannot be changed here (%s)", hint)
	}
	for _, l := range []struct {
		name     string
		now, was []string
	}{
		{"names", d.Names, cur.Names}, {"images", d.Images, cur.Images},
		{"networks", d.Networks, cur.Networks}, {"ports", d.Ports, cur.Ports},
		{"labels", d.Labels, cur.Labels},
	} {
		if len(l.now) == 0 && len(l.was) > 0 && l.name != "ports" && l.name != "labels" {
			return fmt.Errorf("%s: a list cannot be emptied here, because an empty one means the defaults (%s)", l.name, hint)
		}
		if err := subset(l.name, l.now, l.was); err != nil {
			return err
		}
	}
	if len(cur.HostIPs) > 0 { // an empty list is unrestricted, so only a listed one is a limit to keep
		if len(d.HostIPs) == 0 {
			return fmt.Errorf("host_ips: clearing the list removes the limit (%s)", hint)
		}
		if err := subset("host_ips", d.HostIPs, cur.HostIPs); err != nil {
			return err
		}
	}
	if d.Exec && !cur.Exec {
		return fmt.Errorf("exec cannot be turned on here (%s)", hint)
	}
	if cur.PinDigests && d.PinDigests != nil && !*d.PinDigests {
		return fmt.Errorf("pin_digests cannot be turned off here (%s)", hint)
	}
	max := cur.MaxScopes
	if max <= 0 {
		max = 32 // the guard's default
	}
	if d.MaxScopes > max {
		return fmt.Errorf("max_scopes cannot be raised above %d here (%s)", max, hint)
	}
	return nil
}

// SetPolicy validates and rewrites policy.yaml. The guard reads the same file and applies it within
// seconds; a managed game that no longer fits is dropped by the guard, not here.
func (m *Manager) SetPolicy(d PolicyDoc) error {
	if !m.PolicyEditable {
		return errors.New("the policy is read-only here: it is edited in policy.yaml on the host")
	}
	// An exception loosens the guard for one container, so only the file on the host can add or change one.
	d.Exceptions = nil
	cur, curErr := m.filePolicy()
	if curErr == nil {
		d.Exceptions = cur.Exceptions
	}
	if d.PinDigests == nil { // not sent: keep the file's setting
		keep := curErr == nil && cur.PinDigests
		d.PinDigests = &keep
	}
	if curErr != nil {
		return fmt.Errorf("the current policy cannot be read, so it cannot be narrowed: %w", curErr)
	}
	if err := narrowOnly(cur, d); err != nil {
		return err
	}
	body, err := yaml.Marshal(d)
	if err != nil {
		return err
	}
	doc := append([]byte("# Operator-owned envelope for what the dashboard may add. Last written from the dashboard.\n"+
		"# Docs: docs/modules.md in the CrowsNest repo. Every list is required: no limit is ever implied.\n"), body...)
	if _, err := dockerguard.ParsePolicy(doc); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	dir := filepath.Dir(m.PolicyFile)
	tmp, err := os.CreateTemp(dir, ".policy-*.yaml")
	if err != nil {
		return fmt.Errorf("the policy folder is not writable by the panel: %w", err)
	}
	defer os.Remove(tmp.Name()) // #nosec G104 -- best effort once renamed away
	if _, err := tmp.Write(doc); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), m.PolicyFile)
}
