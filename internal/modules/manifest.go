package modules

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/fiddler110/crowsnest/internal/games"
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

	Players struct {
		Type string `yaml:"type"`
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
var supportedPlayers = map[string]bool{"": true, "none": true}

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
	return func(def *games.GameDef, _ Env) []Runner {
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
		return nil
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
		b, err := os.ReadFile(filepath.Join(dir, e.Name(), "module.yaml"))
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
