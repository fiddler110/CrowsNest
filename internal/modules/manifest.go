package modules

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/logtrack"
	"github.com/fiddler110/crowsnest/internal/probes"
)

// APIVersion is the module.yaml schema major version this build understands.
const APIVersion = 1

// Manifest is a parsed, validated module.yaml (docs/modularization-plan.md,
// section 2). Step 2 of phase 1 covers identity, restart policy, startup
// milestones and the probe type declaration; the probe engines themselves
// (log_markers, http_json, source_rcon) land in step 3.
type Manifest struct {
	APIVersion int    `yaml:"api_version"`
	ID         string `yaml:"id"`
	Name       string `yaml:"name"`
	// Description is one or two sentences the dashboard shows in the catalogue.
	Description string `yaml:"description"`
	// Accent is an optional "#rrggbb" colour for the game's dashboard card.
	Accent string `yaml:"accent"`

	Runtime Runtime `yaml:"runtime"`

	// Connect lists values from a game's options that players need to join (a
	// join password, an invite code). For games enabled from the dashboard they
	// are shown on the game's card, as connect_secrets are for config.yaml games.
	Connect []struct {
		Label  string `yaml:"label"`
		Option string `yaml:"option"`
	} `yaml:"connect"`

	// HostSetup lists the steps an operator must do on the host themselves for
	// this game, because the dashboard cannot (and should not) do them: creating
	// a network, a firewall rule. Shown beside the form, in order, with {id} and
	// {option} replaced by what was typed in it (an unset option shows as <option>).
	HostSetup []HostStep `yaml:"host_setup"`

	// Backup is the command (run with docker exec) that backs this game up and
	// the folder its backups land in. Used for games enabled from the dashboard,
	// whose config has no backup block: execguard allows exactly this command in
	// that game's container and nothing else. Games in config.yaml keep their own
	// backup block.
	Backup *config.BackupConfig `yaml:"backup"`

	// Status.ReadyLog is the log line that marks the server open; with
	// players.type log_markers it drives starting/online from the log.
	Status struct {
		ReadyLog string `yaml:"ready_log"`
	} `yaml:"status"`

	Players struct {
		Type  string `yaml:"type"`
		Join  string `yaml:"join"`  // regexp, group 1 = player id
		Leave string `yaml:"leave"` // regexp, group 1 = player id
		World string `yaml:"world"` // regexp, group 1 = world name (optional)

		// http_json (needs the api block): Path is polled for the count
		// (and, unless status_path is set, for online/starting). CountPath/
		// NamesPath/NameField pick the fields.
		Path      string `yaml:"path"`
		CountPath string `yaml:"count_path"`
		NamesPath string `yaml:"names_path"`
		NameField string `yaml:"name_field"`

		// source_rcon: run Command at Addr, each line matching Pattern
		// (group 1 = name) is one player. Password from PasswordEnv.
		Addr        string `yaml:"addr"`
		PasswordEnv string `yaml:"password_env"`
		Command     string `yaml:"command"`
		Pattern     string `yaml:"pattern"`
	} `yaml:"players"`

	// Options declares the per-game settings a config.yaml entry may give
	// under "options:". ${key} in api/rcon/players string fields is replaced
	// by the value (or the default).
	Options []Option `yaml:"options"`

	// API is the game's JSON-over-HTTP admin API (players.type http_json,
	// info, actions and pre_stop all use it). If a required option is unset
	// the API is left unwired and the game keeps the baseline.
	API struct {
		BaseURL     string `yaml:"base_url"`
		User        string `yaml:"user"`
		PasswordEnv string `yaml:"password_env"` // env var holding the password
		StatusPath  string `yaml:"status_path"`  // default players.path
	} `yaml:"api"`

	Info struct {
		Sources []probes.InfoSource `yaml:"sources"`
		Fields  []probes.InfoField  `yaml:"fields"`
	} `yaml:"info"`

	Actions []probes.Action `yaml:"actions"`
	PreStop []probes.Step   `yaml:"pre_stop"`

	// RCON enables the admin-only raw console. Empty addr (after option
	// substitution) leaves it off.
	RCON struct {
		Addr        string `yaml:"addr"`
		PasswordEnv string `yaml:"password_env"`
	} `yaml:"rcon"`

	Startup []StartupStep `yaml:"startup"`

	// StartupProgress reads a percentage out of a log line (e.g. SteamCMD's
	// "Update state (0x61) downloading, progress: 42.5") and maps 0-100 onto
	// From..To of the startup bar. Label may contain {pct}.
	StartupProgress *StartupProgress `yaml:"startup_progress"`
}

// HostStep is one thing to do on the host.
type HostStep struct {
	Title   string `yaml:"title"`
	Detail  string `yaml:"detail"`
	Command string `yaml:"command"` // optional, shown to copy
}

// StartupProgress is a percentage parsed from the log and scaled onto a range.
type StartupProgress struct {
	Match string `yaml:"match"` // regexp, group 1 = number
	From  int    `yaml:"from"`
	To    int    `yaml:"to"`
	Label string `yaml:"label"`
}

// Option is one declared per-game setting.
type Option struct {
	Key      string `yaml:"key"`
	Label    string `yaml:"label"`
	Default  string `yaml:"default"`
	Required bool   `yaml:"required"`
	// Secret marks a value that must never be written into a rendered file:
	// it is referenced as a variable in .env instead.
	Secret bool `yaml:"secret"`
	// Derive fills the option in when the operator leaves it empty, so wiring
	// that follows from the game itself is never typed in. {id} is the game's
	// id (also its container name and hostname on the games network) and
	// {env:KEY} is the name of the variable that holds secret option KEY.
	// An option with a Derive is never required.
	Derive string `yaml:"derive"`
	// ManagedRequired makes the option required for games enabled from the dashboard only
	// (a config.yaml game wires the same thing by hand, so it may leave it out).
	ManagedRequired bool `yaml:"managed_required"`
}

// StartupStep maps a log pattern to a startup progress percentage.
type StartupStep struct {
	Match string `yaml:"match"`
	Pct   int    `yaml:"pct"`
	Label string `yaml:"label"`
}

var idRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

var accentRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// supportedPlayers lists the probe types an engine exists for. Declared types
// beyond these are refused until their engine lands.
var supportedPlayers = map[string]bool{"": true, "none": true, "log_markers": true, "http_json": true, "source_rcon": true}

// Parse decodes and validates one module.yaml. Unknown keys are an error so a
// typo in a manifest cannot silently disable a setting.
func Parse(r io.Reader) (*Manifest, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("module.yaml: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

var actionIDRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// validateREST checks the actions, info and pre_stop sections.
func (m *Manifest) validateREST() error {
	checkReq := func(where string, r probes.Request) error {
		switch r.Method {
		case "", "GET", "POST", "PUT", "DELETE":
		default:
			return fmt.Errorf("module %q: %s: method %q not allowed", m.ID, where, r.Method)
		}
		if !strings.HasPrefix(r.Path, "/") {
			return fmt.Errorf("module %q: %s: path must start with /", m.ID, where)
		}
		return nil
	}
	ids := map[string]bool{}
	for i, a := range m.Actions {
		w := fmt.Sprintf("actions[%d]", i)
		if !actionIDRe.MatchString(a.ID) || ids[a.ID] || a.Label == "" {
			return fmt.Errorf("module %q: %s needs a unique id [a-z0-9_] and a label", m.ID, w)
		}
		ids[a.ID] = true
		if err := checkReq(w, a.Request); err != nil {
			return err
		}
		names := map[string]bool{}
		for _, f := range a.Fields {
			if f.Name == "" || names[f.Name] || f.Max < 0 {
				return fmt.Errorf("module %q: %s has a bad field %q", m.ID, w, f.Name)
			}
			names[f.Name] = true
		}
		if a.List != nil && (a.List.Path == "" || a.List.Line == "") {
			return fmt.Errorf("module %q: %s list needs path and line", m.ID, w)
		}
	}
	for i, st := range m.PreStop {
		if err := checkReq(fmt.Sprintf("pre_stop[%d]", i), st.Request); err != nil {
			return err
		}
		if st.Pause < 0 || st.Pause > time.Minute {
			return fmt.Errorf("module %q: pre_stop[%d].pause must be 0-1m", m.ID, i)
		}
	}
	srcs := map[string]bool{}
	for _, src := range m.Info.Sources {
		if src.Name == "" || srcs[src.Name] || !strings.HasPrefix(src.Path, "/") {
			return fmt.Errorf("module %q: info source %q needs a unique name and a path starting with /", m.ID, src.Name)
		}
		srcs[src.Name] = true
	}
	for _, f := range m.Info.Fields {
		if f.Key == "" || f.Template == "" {
			return fmt.Errorf("module %q: info fields need key and template", m.ID)
		}
	}
	return nil
}

func (m *Manifest) validate() error {
	if m.APIVersion != APIVersion {
		return fmt.Errorf("module %q: api_version %d not supported (this build speaks %d)", m.ID, m.APIVersion, APIVersion)
	}
	if !idRe.MatchString(m.ID) {
		return fmt.Errorf("module id %q must match %s", m.ID, idRe)
	}
	if m.Name == "" {
		return fmt.Errorf("module %q: name is required", m.ID)
	}
	if m.Accent != "" && !accentRe.MatchString(m.Accent) {
		return fmt.Errorf("module %q: accent %q must be a colour like \"#60a5fa\"", m.ID, m.Accent)
	}
	if m.Backup != nil {
		if len(m.Backup.Exec) == 0 || m.Backup.Exec[0] == "" {
			return fmt.Errorf("module %q: backup.exec must be a command", m.ID)
		}
		if err := m.Backup.CheckKeep(); err != nil {
			return fmt.Errorf("module %q: backup: %w", m.ID, err)
		}
		if m.Backup.ListDir != "" && !strings.HasPrefix(m.Backup.ListDir, "/") {
			return fmt.Errorf("module %q: backup.list_dir must be an absolute path", m.ID)
		}
	}
	if m.Runtime.RestartCooldown < 0 {
		return fmt.Errorf("module %q: restart_cooldown must not be negative", m.ID)
	}
	for field, v := range map[string]string{"runtime.ram": m.Runtime.RAM, "runtime.memory": m.Runtime.Memory} {
		if v == "" {
			continue
		}
		if _, err := SizeBytes(field, v); err != nil {
			return fmt.Errorf("module %q: %w", m.ID, err)
		}
	}
	declared := map[string]bool{}
	for _, o := range m.Options {
		declared[o.Key] = true
	}
	for _, n := range m.Runtime.Networks {
		if !declared[n.NameOption] || (n.IPv4Option != "" && !declared[n.IPv4Option]) {
			return fmt.Errorf("module %q: runtime.networks must name declared options", m.ID)
		}
	}
	if o := m.Runtime.GamesIPv4Option; o != "" && !declared[o] {
		return fmt.Errorf("module %q: runtime.games_ipv4_option %q is not a declared option", m.ID, o)
	}
	for _, o := range m.Runtime.SecOpts {
		if o == "" || strings.ContainsAny(o, " ,") {
			return fmt.Errorf("module %q: bad runtime.secopts entry %q", m.ID, o)
		}
	}
	if !supportedPlayers[m.Players.Type] {
		return fmt.Errorf("module %q: players.type %q is not supported yet", m.ID, m.Players.Type)
	}
	if m.Players.Type == "log_markers" {
		if m.Status.ReadyLog == "" || m.Players.Join == "" || m.Players.Leave == "" {
			return fmt.Errorf("module %q: log_markers needs status.ready_log, players.join and players.leave", m.ID)
		}
		for name, re := range map[string]string{"status.ready_log": m.Status.ReadyLog, "players.join": m.Players.Join, "players.leave": m.Players.Leave, "players.world": m.Players.World} {
			if re == "" {
				continue
			}
			if c, err := regexp.Compile(re); err != nil {
				return fmt.Errorf("module %q: %s invalid: %v", m.ID, name, err)
			} else if name != "status.ready_log" && c.NumSubexp() < 1 {
				return fmt.Errorf("module %q: %s needs a capture group", m.ID, name)
			}
		}
	}
	seen := map[string]bool{}
	for _, o := range m.Options {
		if o.Key == "" || seen[o.Key] {
			return fmt.Errorf("module %q: option key %q is empty or duplicated", m.ID, o.Key)
		}
		seen[o.Key] = true
	}
	hasAPI := m.API.BaseURL != ""
	if (len(m.Info.Fields) > 0 || len(m.Actions) > 0 || len(m.PreStop) > 0 || m.Players.Type == "http_json") && !hasAPI {
		return fmt.Errorf("module %q: http_json, info, actions and pre_stop need api.base_url", m.ID)
	}
	if hasAPI && !strings.HasPrefix(m.API.BaseURL, "http://") && !strings.HasPrefix(m.API.BaseURL, "https://") && !strings.HasPrefix(m.API.BaseURL, "${") {
		return fmt.Errorf("module %q: api.base_url must be http(s) or an ${option}", m.ID)
	}
	if err := m.validateREST(); err != nil {
		return err
	}
	switch m.Players.Type {
	case "http_json":
		if m.Players.Path == "" || m.Players.CountPath == "" {
			return fmt.Errorf("module %q: http_json needs players.path and players.count_path", m.ID)
		}
	case "source_rcon":
		if m.Players.Addr == "" || m.Players.Command == "" || m.Players.Pattern == "" {
			return fmt.Errorf("module %q: source_rcon needs players.addr, command and pattern", m.ID)
		}
		if _, err := regexp.Compile(m.Players.Pattern); err != nil {
			return fmt.Errorf("module %q: players.pattern invalid: %v", m.ID, err)
		}
	}
	if sp := m.StartupProgress; sp != nil {
		c, err := regexp.Compile(sp.Match)
		if err != nil || sp.Match == "" || c.NumSubexp() < 1 {
			return fmt.Errorf("module %q: startup_progress.match must be a regexp with a capture group", m.ID)
		}
		if sp.From < 0 || sp.To > 100 || sp.From >= sp.To {
			return fmt.Errorf("module %q: startup_progress needs 0 <= from < to <= 100", m.ID)
		}
	}
	for i, s := range m.Startup {
		if _, err := regexp.Compile(s.Match); err != nil || s.Match == "" {
			return fmt.Errorf("module %q: startup[%d].match invalid: %v", m.ID, i, err)
		}
		if s.Pct < 0 || s.Pct > 100 {
			return fmt.Errorf("module %q: startup[%d].pct %d out of range 0-100", m.ID, i, s.Pct)
		}
	}
	return nil
}

// Wire returns the WireFunc that applies the manifest to a baseline GameDef.
func (m *Manifest) Wire() WireFunc {
	return func(def *games.GameDef, env Env) []Runner {
		var runners []Runner
		if m.Accent != "" {
			def.Accent = m.Accent
		}
		if m.Players.Type == "log_markers" {
			spec := logtrack.Spec{
				Name:  m.ID,
				Ready: regexp.MustCompile(m.Status.ReadyLog),
				Join:  regexp.MustCompile(m.Players.Join),
				Leave: regexp.MustCompile(m.Players.Leave),
			}
			if m.Players.World != "" {
				spec.World = regexp.MustCompile(m.Players.World)
			}
			tr := logtrack.New(env.Docker, def.ContainerName, spec)
			def.Status, def.Players, def.Info = tr, tr, tr
			runners = append(runners, tr)
		}
		opts := newOptions(m, env.Config.Options)
		if m.API.BaseURL != "" {
			if missing := opts.missingRequired(); len(missing) > 0 {
				log.Printf("%s: option(s) %s not set in config.yaml; API integration is off", m.ID, strings.Join(missing, ", "))
			} else {
				api := &probes.HTTPJSON{
					Docker: env.Docker, Name: m.ID,
					BaseURL: strings.TrimRight(opts.sub(m.API.BaseURL), "/"),
					User:    opts.sub(m.API.User), Pass: env.Secret(opts.sub(m.API.PasswordEnv)),
					StatusPath: m.API.StatusPath, PlayersPath: m.Players.Path,
					CountPath: m.Players.CountPath, NamesPath: m.Players.NamesPath, NameField: m.Players.NameField,
					InfoSources: m.Info.Sources, InfoFields: m.Info.Fields,
					ActionDefs: m.Actions, Steps: m.PreStop,
				}
				def.Status = api
				if m.Players.Type == "http_json" {
					def.Players = api
				}
				if len(m.Info.Fields) > 0 {
					def.Info = api
				}
				if len(m.Actions) > 0 {
					def.Console = api
				}
				if len(m.PreStop) > 0 {
					def.PreStop = api
				}
			}
		}
		if addr := opts.sub(m.RCON.Addr); addr != "" {
			def.RawConsole = &probes.RawRCON{Addr: addr, Password: env.Secret(opts.sub(m.RCON.PasswordEnv))}
		}
		switch m.Players.Type {
		case "source_rcon":
			if addr := opts.sub(m.Players.Addr); addr == "" {
				log.Printf("%s: players.addr is empty (option not set in config.yaml); player count stays unknown", m.ID)
			} else {
				def.Players = &probes.SourceRCON{
					Addr: addr, Password: env.Secret(opts.sub(m.Players.PasswordEnv)),
					Command: m.Players.Command, Pattern: regexp.MustCompile(m.Players.Pattern),
				}
			}
		}
		if m.Runtime.RestartCooldown > 0 {
			def.RestartCooldown = m.Runtime.RestartCooldown
		}
		def.RAMEstimate = ramEstimate(m, env.Config.Options)
		if len(m.Startup) > 0 || m.StartupProgress != nil {
			sm := &games.StartupMatcher{}
			if sp := m.StartupProgress; sp != nil {
				re := regexp.MustCompile(sp.Match)
				sm.Parse = func(line string) (int, string, bool) {
					g := re.FindStringSubmatch(line)
					if g == nil {
						return 0, "", false
					}
					v, err := strconv.ParseFloat(g[1], 64)
					if err != nil {
						return 0, "", false
					}
					return sp.From + int(v*float64(sp.To-sp.From)/100), strings.ReplaceAll(sp.Label, "{pct}", fmt.Sprintf("%.0f", v)), true
				}
			}
			for _, s := range m.Startup {
				sm.Milestones = append(sm.Milestones, games.Milestone{
					Pattern: regexp.MustCompile(s.Match), Pct: s.Pct, Label: s.Label,
				})
			}
			def.Startup = sm
		}
		return runners
	}
}

// LoadDir reads every <dir>/<id>/module.yaml and registers it in s. The
// directory name must equal the manifest id. A missing dir is not an error
// (no local modules); a bad manifest is, and nothing from it is registered.
func (s *Set) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	bad, err := verifyLocked(dir)
	if err != nil {
		return err
	}
	var ms []*Manifest
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if why, no := bad[e.Name()]; no {
			log.Printf("modules: %q not loaded: %s", e.Name(), why)
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name(), "module.yaml")) // #nosec G304 -- dir is the operator-set modules_dir and e.Name() comes from listing it
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		m, err := Parse(bytes.NewReader(b))
		if err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
		if m.ID != e.Name() {
			return fmt.Errorf("%s: directory name must equal module id %q", e.Name(), m.ID)
		}
		if _, dup := s.wire[m.ID]; dup {
			return fmt.Errorf("%s: module %q is already registered", e.Name(), m.ID)
		}
		ms = append(ms, m)
	}
	for _, m := range ms {
		s.Register(m.ID, m.Wire())
		s.manifests[m.ID] = m
	}
	return nil
}

// options resolves ${key} placeholders from a game's config options, falling
// back to the manifest defaults.
type options struct {
	m    *Manifest
	vals map[string]string
}

var optRe = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)

func newOptions(m *Manifest, given map[string]string) *options {
	v := map[string]string{}
	for _, o := range m.Options {
		v[o.Key] = o.Default
	}
	for k, val := range given {
		if _, known := v[k]; known {
			v[k] = val
		}
	}
	return &options{m: m, vals: v}
}

func (o *options) sub(s string) string {
	return optRe.ReplaceAllStringFunc(s, func(tok string) string { return o.vals[optRe.FindStringSubmatch(tok)[1]] })
}

func (o *options) missingRequired() []string {
	var out []string
	for _, d := range o.m.Options {
		if d.Required && o.vals[d.Key] == "" {
			out = append(out, d.Key)
		}
	}
	return out
}

// ramEstimate is the game's declared memory need in bytes: the instance's ram
// option, else runtime.ram, else the runtime.memory limit; zero when none is
// set or the instance's value does not parse (the loader logs that).
func ramEstimate(m *Manifest, given map[string]string) uint64 {
	v := given["ram"]
	field := "ram option"
	if v == "" {
		v, field = m.Runtime.RAM, "runtime.ram"
	}
	if v == "" {
		v, field = m.Runtime.Memory, "runtime.memory"
	}
	if v == "" {
		return 0
	}
	n, err := SizeBytes(field, v)
	if err != nil {
		log.Printf("%s: %v; memory admission skips this game", m.ID, err)
		return 0
	}
	if n < 0 {
		return 0
	}
	return uint64(n)
}
