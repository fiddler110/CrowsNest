package modules

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"

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

	Runtime struct {
		RestartCooldown time.Duration `yaml:"restart_cooldown"`
	} `yaml:"runtime"`

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

		// http_json: poll URL (also the online check); PlayersURL overrides
		// it for the count. CountPath/NamesPath/NameField pick fields.
		URL         string `yaml:"url"`
		PlayersURL  string `yaml:"players_url"`
		User        string `yaml:"user"`
		PasswordEnv string `yaml:"password_env"` // env var holding the password
		CountPath   string `yaml:"count_path"`
		NamesPath   string `yaml:"names_path"`
		NameField   string `yaml:"name_field"`

		// source_rcon: run Command at Addr, each line matching Pattern
		// (group 1 = name) is one player. Password from PasswordEnv.
		Addr    string `yaml:"addr"`
		Command string `yaml:"command"`
		Pattern string `yaml:"pattern"`
	} `yaml:"players"`

	Startup []StartupStep `yaml:"startup"`
}

// StartupStep maps a log pattern to a startup progress percentage.
type StartupStep struct {
	Match string `yaml:"match"`
	Pct   int    `yaml:"pct"`
	Label string `yaml:"label"`
}

var idRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

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
	if m.Runtime.RestartCooldown < 0 {
		return fmt.Errorf("module %q: restart_cooldown must not be negative", m.ID)
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
	switch m.Players.Type {
	case "http_json":
		if u, err := url.Parse(m.Players.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("module %q: players.url must be an http(s) URL", m.ID)
		}
		if m.Players.PlayersURL != "" {
			if u, err := url.Parse(m.Players.PlayersURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("module %q: players.players_url must be an http(s) URL", m.ID)
			}
		}
		if m.Players.CountPath == "" {
			return fmt.Errorf("module %q: http_json needs players.count_path", m.ID)
		}
	case "source_rcon":
		if m.Players.Addr == "" || m.Players.Command == "" || m.Players.Pattern == "" {
			return fmt.Errorf("module %q: source_rcon needs players.addr, command and pattern", m.ID)
		}
		if _, err := regexp.Compile(m.Players.Pattern); err != nil {
			return fmt.Errorf("module %q: players.pattern invalid: %v", m.ID, err)
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
		switch m.Players.Type {
		case "http_json":
			p := &probes.HTTPJSON{
				Docker: env.Docker, URL: m.Players.URL, PlayersURL: m.Players.PlayersURL,
				User: m.Players.User, Pass: os.Getenv(m.Players.PasswordEnv),
				CountPath: m.Players.CountPath, NamesPath: m.Players.NamesPath, NameField: m.Players.NameField,
			}
			def.Status, def.Players = p, p
		case "source_rcon":
			def.Players = &probes.SourceRCON{
				Addr: m.Players.Addr, Password: os.Getenv(m.Players.PasswordEnv),
				Command: m.Players.Command, Pattern: regexp.MustCompile(m.Players.Pattern),
			}
		}
		if m.Runtime.RestartCooldown > 0 {
			def.RestartCooldown = m.Runtime.RestartCooldown
		}
		if len(m.Startup) > 0 {
			sm := &games.StartupMatcher{}
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
	var ms []*Manifest
	for _, e := range entries {
		if !e.IsDir() {
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
	}
	return nil
}
