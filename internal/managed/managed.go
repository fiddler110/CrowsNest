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
	PolicyFile string // operator's policy.yaml (read only)
	Platform   modules.Platform
	Modules    *modules.Set
	Config     *config.Config
	Docker     Docker
	Wire       *dockerctl.Client // for module wiring (status, logs, exec)
	Registry   *games.Registry
	// Settle is how long a new game waits for the guard to pick up its scope.
	Settle time.Duration
	// Busy, when set, reports a game that is mid start/stop. A start still
	// pulling has no container yet, so Docker.Running alone would miss it.
	Busy func(id string) bool

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
}

// Info is a managed game as the dashboard lists it.
type Info struct {
	ID     string `json:"id"`
	Module string `json:"module"`
	State  string `json:"state"` // installing, ready, failed
	Error  string `json:"error,omitempty"`
}

// Plan is the dry-run of a Request.
type Plan struct {
	Service string   `json:"service"` // the compose service
	Scope   string   `json:"scope"`   // the guard scope
	Env     []string `json:"env"`     // .env variables the service reads
	Fits    bool     `json:"fits"`    // inside the operator's policy
	Reason  string   `json:"reason,omitempty"`
}

// OptionInfo and ModuleInfo describe the catalogue to the dashboard.
type OptionInfo struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Default  string `json:"default,omitempty"`
	Required bool   `json:"required,omitempty"`
	Secret   bool   `json:"secret,omitempty"`
}

type ModuleInfo struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	NeedsImage bool         `json:"needs_image"` // the module has no image of its own
	Options    []OptionInfo `json:"options"`
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
		mi := ModuleInfo{ID: mf.ID, Name: mf.Name, NeedsImage: mf.Runtime.Image == ""}
		for _, o := range mf.Options {
			mi.Options = append(mi.Options, OptionInfo{Key: o.Key, Label: o.Label, Default: o.Default, Required: o.Required, Secret: o.Secret})
		}
		out = append(out, mi)
	}
	return out
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
		if !o.Required {
			continue
		}
		if o.Secret {
			if r.Secrets[o.Key] == "" && !existing {
				return g, nil, fmt.Errorf("option %q is required", o.Key)
			}
		} else if opts[o.Key] == "" && o.Default == "" {
			return g, nil, fmt.Errorf("option %q is required", o.Key)
		}
	}
	if mf.Runtime.Image == "" && opts["image"] == "" {
		return g, nil, fmt.Errorf("module %s has no image of its own: set the image option", mf.ID)
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

// Preview renders a Request without changing anything.
func (m *Manager) Preview(r Request) (*Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
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
	p := &Plan{Service: string(svc), Scope: string(sc), Fits: fitErr == nil}
	if fitErr != nil {
		p.Reason = fitErr.Error()
	}
	for _, v := range rd.EnvVars {
		p.Env = append(p.Env, v.Name)
	}
	return p, nil
}

// Enable records the game and installs it in the background: scope, image,
// container, then it joins the dashboard. It returns once the request is
// accepted; List shows the progress.
func (m *Manager) Enable(r Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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

var errBusy = errors.New("the game is starting or stopping; wait for it to finish")

func (m *Manager) reinstall(r Request, refresh bool) error {
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
		out = append(out, Info{ID: e.ID, Module: e.Module, State: e.State, Error: e.Error})
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
