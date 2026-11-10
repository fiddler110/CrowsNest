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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
}

// Manager owns the dashboard-enabled games.
type Manager struct {
	Dir        string // state directory
	PolicyFile string // operator's policy.yaml
	// PolicyEditable lets SetPolicy rewrite PolicyFile (the operator mounted it writable and opted in).
	PolicyEditable bool
	Platform       modules.Platform
	Modules        *modules.Set
	Config         *config.Config
	Docker         Docker
	Wire           *dockerctl.Client // for module wiring (status, logs, exec)
	Registry       *games.Registry
	// Settle is how long a new game waits for the guard to pick up its scope.
	Settle time.Duration

	mu      sync.Mutex
	ctx     context.Context
	entries []*entry
}

type entry struct {
	Request
	State string `json:"state"`
	Error string `json:"error,omitempty"`

	rendered *modules.Rendered
	stop     context.CancelFunc
}

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
	ConnectAddress string            `json:"connect_address,omitempty"`
	Options        map[string]string `json:"options,omitempty"`
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
	Folders   []string `json:"folders,omitempty"` // host folders the game stores data in
	Memory    string   `json:"memory,omitempty"`
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

type ModuleInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	NeedsImage  bool     `json:"needs_image"` // the module has no image of its own
	Description string   `json:"description,omitempty"`
	Image       string   `json:"image,omitempty"`
	Ports       []string `json:"ports,omitempty"` // "25565/tcp"
	HasBackup   bool     `json:"has_backup,omitempty"`
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
	reserve = map[string]bool{"image": true, "tag": true, "ports": true, "data_dir": true}
)

// Catalogue lists the modules that can be enabled from the dashboard: those
// that describe a container (a runtime section).
func (m *Manager) Catalogue() []ModuleInfo {
	var out []ModuleInfo
	for _, mf := range m.Modules.Manifests() {
		if len(mf.Runtime.Ports) == 0 && mf.Runtime.Image == "" && len(mf.Runtime.Data) == 0 {
			continue
		}
		rt := mf.Runtime
		mi := ModuleInfo{ID: mf.ID, Name: mf.Name, NeedsImage: mf.Runtime.Image == "",
			NeedsException: len(rt.SecOpts) > 0 || len(rt.Networks) > 0 || rt.GamesIPv4Option != "",
			Description:    mf.Description, Image: mf.Runtime.Image, HasBackup: mf.Backup != nil}
		for _, p := range mf.Runtime.Ports {
			mi.Ports = append(mi.Ports, fmt.Sprintf("%d/%s", p.Port, p.Proto))
		}
		if len(mf.Runtime.Ports) > 0 && m.Platform.HostIP != "" && m.Platform.HostIP != "0.0.0.0" {
			mi.ConnectHint = fmt.Sprintf("%s:%d", m.Platform.HostIP, mf.Runtime.Ports[0].Port)
		}
		for _, o := range mf.Options {
			mi.Options = append(mi.Options, OptionInfo{Key: o.Key, Label: o.Label, Default: o.Default, Required: (o.Required || o.ManagedRequired) && o.Derive == "", Secret: o.Secret, Auto: o.Derive != ""})
		}
		m.probeFit(&mi, mf)
		out = append(out, mi)
	}
	return out
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
	mf, ok := m.Modules.Manifest(r.Module)
	if !ok {
		return g, nil, fmt.Errorf("module %q is not installed", r.Module)
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
		ConnectAddress: r.ConnectAddress, Options: opts, Backup: mf.Backup,
	}
	if g.DisplayName == "" {
		g.DisplayName = mf.Name
	}
	if rd, err := mf.Render(g, m.Platform); err == nil && !r.probe { // a catalogue probe asks about the policy, not the ports in use
		if clash := m.portClash(g.ID, rd); clash != "" {
			return g, nil, errors.New(clash)
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

func (m *Manager) policy() (*dockerguard.Policy, error) {
	if m.PolicyFile == "" {
		return nil, errors.New("no policy file is configured: managed games need an operator policy")
	}
	return dockerguard.LoadPolicy(m.PolicyFile)
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

// withDefaults gives a new game its own data folder: <module folder>-<id>. Two games from one module must
// never share a folder (they would write the same world), and a new game must not land in a folder an
// existing hand-set-up server already uses. A folder typed in the form is kept.
func (m *Manager) withDefaults(r Request) Request {
	mf, ok := m.Modules.Manifest(r.Module)
	if !ok || r.Options["data_dir"] != "" || r.ID == "" {
		return r
	}
	base := mf.Runtime.DataDir
	if base == "" {
		base = mf.Name
	}
	opts := make(map[string]string, len(r.Options)+1)
	for k, v := range r.Options {
		opts[k] = v
	}
	opts["data_dir"] = base + "-" + r.ID
	r.Options = opts
	return r
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
	p := &Plan{Service: string(svc), Scope: string(sc), Fits: fitErr == nil,
		Container: rd.Service.ContainerName, Image: rd.Service.Image, Ports: rd.Service.Ports, Memory: rd.Service.MemLimit}
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
	spec, err := rd.Spec(m.lookup(e))
	if err == nil {
		err = m.writeScopes()
	}
	m.mu.Unlock()
	if err != nil {
		return err
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	exists, err := m.Docker.Exists(ctx, spec.Name)
	if err != nil {
		return err
	}
	if exists && mode.recreate {
		if err := m.Docker.Remove(ctx, spec.Name); err != nil {
			return fmt.Errorf("remove the old container: %w", err)
		}
		exists = false
	}
	if !exists {
		// The guard reloads on its own schedule; until it has our scope it answers 403.
		if err := m.retryDenied(ctx, func() error { return m.Docker.Pull(ctx, spec.Image) }); err != nil {
			if mode.recreate && !mode.pull && !dockerctl.IsDenied(err) {
				log.Printf("managed: pull %s failed, using the local image: %v", spec.Image, err)
			} else {
				return fmt.Errorf("pull %s: %w", spec.Image, err)
			}
		}
		if err := m.retryDenied(ctx, func() error { return m.Docker.Create(ctx, spec) }); err != nil {
			return fmt.Errorf("create container: %w", err)
		}
	}
	return m.register(e, g)
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

// lookup resolves a compose variable: the game's own secrets, then the panel's environment.
func (m *Manager) lookup(e *entry) func(string) (string, bool) {
	secrets := m.secretsFor(e)
	return func(name string) (string, bool) {
		if v, ok := secrets[name]; ok {
			return v, true
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
	secrets := m.secretsFor(e)
	lookup := func(name string) string {
		if v, ok := secrets[name]; ok {
			return v
		}
		return os.Getenv(name)
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
func (m *Manager) Update(r Request) error { return m.reinstall(r, false) }

// Refresh pulls the game's image again and recreates its container with the
// same settings.
func (m *Manager) Refresh(id string) error { return m.reinstall(Request{ID: id}, true) }

func (m *Manager) reinstall(r Request, refresh bool) error {
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
	e.Request, e.rendered, e.State, e.Error = next, rd, StateInstalling, ""
	if err := m.save(); err != nil {
		return err
	}
	go m.install(e, g, installMode{recreate: true, pull: refresh})
	return nil
}

// Disable removes a stopped game: its container, dashboard entry, scope and
// secrets. Its data folder is left untouched.
func (m *Manager) Disable(id string) error {
	m.mu.Lock()
	e := m.find(id)
	m.mu.Unlock()
	if e == nil {
		return fmt.Errorf("game %q is not a dashboard-enabled game", id)
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
	if ok, _ := m.Docker.Exists(ctx, id); ok {
		if err := m.Docker.Remove(ctx, id); err != nil {
			return err
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
		out = append(out, Info{ID: e.ID, Module: e.Module, State: e.State, Error: e.Error,
			DisplayName: e.DisplayName, ConnectAddress: e.ConnectAddress, Options: opts})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---- persistence

type stateFile struct {
	Games []struct {
		Request
		State string `json:"state"`
		Error string `json:"error,omitempty"`
	} `json:"games"`
}

func (m *Manager) path(name string) string { return filepath.Join(m.Dir, name) }

// save writes games.json (without secrets) and secrets.json (0600).
func (m *Manager) save() error {
	var st stateFile
	secrets := map[string]map[string]string{}
	for _, e := range m.entries {
		req := e.Request
		req.Secrets = nil
		st.Games = append(st.Games, struct {
			Request
			State string `json:"state"`
			Error string `json:"error,omitempty"`
		}{req, e.State, e.Error})
		if len(e.Secrets) > 0 {
			secrets[e.ID] = e.Secrets
		}
	}
	if err := writeJSON(m.path("games.json"), st, 0o600); err != nil {
		return err
	}
	return writeJSON(m.path("secrets.json"), secrets, 0o600)
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
	type todo struct {
		e *entry
		g config.GameConfig
	}
	var installs []todo
	for _, s := range st.Games {
		req := s.Request
		req.Secrets = secrets[req.ID]
		g, mf, err := m.validate(req, true)
		e := &entry{Request: req, State: s.State, Error: s.Error}
		if err == nil {
			e.rendered, err = mf.Render(g, m.Platform)
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
func ExecRules(dir string, mods *modules.Set) ([]execguard.Rule, error) {
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
		if !ok || mf.Backup == nil || !idRe.MatchString(g.ID) {
			continue
		}
		rules = append(rules, execguard.Rule{Container: g.ID, Cmd: mf.Backup.Exec})
		if mf.Backup.ListDir != "" {
			rules = append(rules, execguard.Rule{Container: g.ID, Cmd: backup.ListArgs(mf.Backup.ListDir)})
		}
	}
	return rules, nil
}

// PolicyDoc is policy.yaml as the dashboard shows and edits it.
type PolicyDoc struct {
	GamesRoot string   `json:"games_root" yaml:"games_root"`
	Names     []string `json:"names" yaml:"names"`
	Images    []string `json:"images" yaml:"images"`
	Networks  []string `json:"networks" yaml:"networks"`
	Ports     []string `json:"ports" yaml:"ports"`
	HostIPs   []string `json:"host_ips" yaml:"host_ips,omitempty"`
	Exec      bool     `json:"exec" yaml:"exec"`
	Labels    []string `json:"labels" yaml:"labels,omitempty"`
	MaxScopes int      `json:"max_scopes" yaml:"max_scopes"`
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
	p, err := m.policy()
	if err != nil {
		return PolicyState{}, err
	}
	return PolicyState{Editable: m.PolicyEditable, Policy: PolicyDoc{
		GamesRoot: p.GamesRoot, Names: p.Names, Images: p.Images, Networks: p.Networks, Ports: p.Ports,
		HostIPs: p.HostIPs, Exec: p.Exec, Labels: p.Labels, MaxScopes: p.MaxScopes, Exceptions: p.Exceptions,
	}}, nil
}

// SetPolicy validates and rewrites policy.yaml. The guard reads the same file and applies it within
// seconds; a managed game that no longer fits is dropped by the guard, not here.
func (m *Manager) SetPolicy(d PolicyDoc) error {
	if !m.PolicyEditable {
		return errors.New("the policy is read-only here: it is edited in policy.yaml on the host")
	}
	// An exception loosens the guard for one container, so only the file on the host can add or change one.
	d.Exceptions = nil
	if cur, err := m.policy(); err == nil {
		d.Exceptions = cur.Exceptions
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
