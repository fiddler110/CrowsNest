package managed

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fiddler110/crowsnest/internal/atomicfile"
	"github.com/fiddler110/crowsnest/internal/gamefiles"
	"os"
	"path/filepath"
	"slices"

	"github.com/fiddler110/crowsnest/internal/backup"
	"github.com/fiddler110/crowsnest/internal/dockerguard"
	"github.com/fiddler110/crowsnest/internal/execguard"
	"github.com/fiddler110/crowsnest/internal/modules"
	"gopkg.in/yaml.v3"
)

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
		if !ok || (mf.Backup == nil && len(mf.Files) == 0) || !idRe.MatchString(g.ID) || !pol.NameAllowed(g.ID) {
			continue
		}
		rules = append(rules, FileRules(g.ID, mf.Files)...)
		if mf.Backup == nil {
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
	if err := atomicfile.Write(m.PolicyFile, doc, 0o644); err != nil {
		return fmt.Errorf("the policy folder is not writable by the panel: %w", err)
	}
	return nil
}

// FileRules are the exec commands that read and write a game's declared files: exactly what gamefiles runs.
func FileRules(container string, specs []gamefiles.Spec) []execguard.Rule {
	var rules []execguard.Rule
	for _, sp := range specs {
		rules = append(rules, execguard.Rule{Container: container, Cmd: sp.ReadArgs()}, execguard.Rule{Container: container, Cmd: sp.WriteArgs()})
	}
	return rules
}
