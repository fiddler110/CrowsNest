package managed

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/fiddler110/crowsnest/internal/dockerguard"
	"github.com/fiddler110/crowsnest/internal/modules"
)

// allowedFile is the modules the operator switched on. The guard reads it
// beside scopes.json and adds those modules' ports to the policy's own.
const allowedFile = "allowed.json"

// Allowed lists the module ids switched on.
func (m *Manager) Allowed() ([]string, error) {
	return dockerguard.ReadAllowed(m.path(allowedFile))
}

// SetAllowed switches a bundled module on or off. What it can widen is bounded:
// the guard only adds ports that a bundled module declares, so the file cannot
// open anything the modules do not already name. Switching off is refused while
// a game from the module exists, because the guard would drop that game.
func (m *Manager) SetAllowed(id string, on bool) error {
	if len(modules.PolicyDefaults(m.Platform).ModulePorts[id]) == 0 {
		return fmt.Errorf("%q is not a bundled module with ports, so its ports can't be allowed here: add them to ports in policy.yaml", id)
	}
	if _, err := m.filePolicy(); err != nil {
		return fmt.Errorf("the policy cannot be read: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, err := m.Allowed()
	if err != nil {
		return err
	}
	has := slices.Contains(cur, id)
	if on == has {
		return nil
	}
	if !on {
		for _, e := range m.entries {
			if e.Module == id {
				return fmt.Errorf("%s still has a game (%s): disable it first, or the guard would drop it", id, e.ID)
			}
		}
		cur = slices.DeleteFunc(cur, func(s string) bool { return s == id })
	} else {
		cur = append(cur, id)
	}
	if cur == nil {
		cur = []string{}
	}
	slices.Sort(cur)
	b, err := json.MarshalIndent(map[string][]string{"modules": cur}, "", "  ")
	if err != nil {
		return err
	}
	if m.Dir == "" {
		return errors.New("no state directory")
	}
	return writeAtomic(m.path(allowedFile), append(b, '\n'), 0o644) // the guard reads this; it holds no secrets
}
