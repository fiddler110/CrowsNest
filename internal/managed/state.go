package managed

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/fiddler110/crowsnest/internal/atomicfile"
	"github.com/fiddler110/crowsnest/internal/vault"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/modules"
)

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
		if e.rendered == nil {
			continue // its module is gone or it no longer renders; it has no scope to issue
		}
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
	return atomicfile.Write(path, b, mode)
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

// ResealSecrets re-encrypts the dashboard games' secrets.json under another vault, for `crowsnest rekey`; it
// returns how many values changed. A missing file is not an error; running it again after an interruption is safe.
// The panel must be stopped.
func ResealSecrets(path string, from, to *vault.Vault) (int, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the managed state folder from the operator's config
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var secrets map[string]map[string]string
	if err := json.Unmarshal(raw, &secrets); err != nil {
		return 0, fmt.Errorf("secrets.json: %w", err)
	}
	n := 0
	for id, kv := range secrets {
		for k, v := range kv {
			out, changed, err := from.Reseal(to, secretPurpose(id, k), v)
			if err != nil {
				return 0, fmt.Errorf("secrets.json (%s, %s): %w", id, k, err)
			}
			if changed {
				kv[k] = out
				n++
			}
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, writeJSON(path, secrets, 0o600)
}
