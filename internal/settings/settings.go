// Package settings holds the CrowsNest options that signed-in users may
// change at runtime from the dashboard (idle timeout, night curfew, how many
// games run at once, auto-update on start). config.yaml supplies the
// defaults; whatever users save is persisted to a small JSON file and wins
// over those defaults from then on, applying immediately without a restart.
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Bounds enforced by Validate.
const (
	MinIdleMinutes = 1
	MaxIdleMinutes = 24 * 60
	MinActiveGames = 1
	MaxActiveGames = 32
)

// Values is the full set of runtime-adjustable options. The JSON tags are
// the wire format for both the settings file and /api/settings.
type Values struct {
	// IdleEnabled stops a running game once it has had zero players for
	// IdleMinutes straight.
	IdleEnabled bool `json:"idle_enabled"`
	IdleMinutes int  `json:"idle_minutes"`

	// NightEnabled stops an empty game during the nightly window, local to
	// server.tz. The window wraps midnight when start > end.
	NightEnabled   bool `json:"night_enabled"`
	NightStartHour int  `json:"night_start_hour"`
	NightEndHour   int  `json:"night_end_hour"`

	// MaxActiveGames is how many games may run at once.
	MaxActiveGames int `json:"max_active_games"`

	// AutoUpdate pulls the latest image for a game each time it is started.
	AutoUpdate bool `json:"auto_update"`

	// RawConsole lets admins send arbitrary RCON commands from the dashboard
	// to games that have an RCON address. Off by default; the fixed-action
	// console is always available to admins.
	RawConsole bool `json:"raw_console"`
}

// Validate reports the first out-of-range field.
func (v Values) Validate() error {
	if v.IdleMinutes < MinIdleMinutes || v.IdleMinutes > MaxIdleMinutes {
		return fmt.Errorf("idle_minutes (%d): must be %d-%d", v.IdleMinutes, MinIdleMinutes, MaxIdleMinutes)
	}
	if v.NightStartHour < 0 || v.NightStartHour > 23 {
		return fmt.Errorf("night_start_hour (%d): must be 0-23", v.NightStartHour)
	}
	if v.NightEndHour < 0 || v.NightEndHour > 23 {
		return fmt.Errorf("night_end_hour (%d): must be 0-23", v.NightEndHour)
	}
	if v.NightEnabled && v.NightStartHour == v.NightEndHour {
		return errors.New("night window: start and end hour must differ")
	}
	if v.MaxActiveGames < MinActiveGames || v.MaxActiveGames > MaxActiveGames {
		return fmt.Errorf("max_active_games (%d): must be %d-%d", v.MaxActiveGames, MinActiveGames, MaxActiveGames)
	}
	return nil
}

// Store is a concurrency-safe, optionally persisted holder of Values.
type Store struct {
	mu   sync.RWMutex
	v    Values
	path string
}

// New builds a Store seeded with defaults. When path is non-empty and the
// file exists, its contents replace the defaults (fields missing from the
// file keep their default). A missing file is fine; an unreadable or
// invalid one is an error, so a typo is noticed rather than silently
// discarded.
func New(defaults Values, path string) (*Store, error) {
	s := &Store{v: defaults, path: path}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("settings: read %s: %w", path, err)
	}
	v := defaults
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("settings: parse %s: %w", path, err)
	}
	if err := v.Validate(); err != nil {
		return nil, fmt.Errorf("settings: %s: %w", path, err)
	}
	s.v = v
	return s, nil
}

// Get returns a snapshot of the current values.
func (s *Store) Get() Values {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v
}

// Update validates v, persists it (atomically: temp file + rename) and, only
// if that succeeds, makes it current.
func (s *Store) Update(v Values) error {
	if err := v.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path != "" {
		if err := writeAtomic(s.path, v); err != nil {
			return err
		}
	}
	s.v = v
	return nil
}

// Modify applies fn to a copy of the current values and, if fn succeeds and
// the result validates, persists and installs it — all under the store's
// lock, so two concurrent partial updates can't overwrite each other. It
// returns the values now in force.
func (s *Store) Modify(fn func(*Values) error) (Values, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.v
	if err := fn(&v); err != nil {
		return s.v, err
	}
	if err := v.Validate(); err != nil {
		return s.v, err
	}
	if s.path != "" {
		if err := writeAtomic(s.path, v); err != nil {
			return s.v, err
		}
	}
	s.v = v
	return v, nil
}

func writeAtomic(path string, v Values) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*")
	if err != nil {
		return fmt.Errorf("settings: save: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("settings: save: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("settings: save: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("settings: save: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("settings: save: %w", err)
	}
	return nil
}
