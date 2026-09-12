// Package exclusivity enforces CrowsNest's "only one game running at a
// time" guarantee: starting a game while another is active is refused with
// a typed conflict instead of racing two containers up together, and
// switching between games is a single serialized stop-then-start
// operation.
package exclusivity

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

const (
	defaultStopPollInterval = 500 * time.Millisecond
	defaultStopPollTimeout  = 30 * time.Second
)

// ConflictError means a start was refused because Active is already
// running or starting. Handlers surface this as HTTP 409.
type ConflictError struct {
	Active string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("exclusivity: %s is already active", e.Active)
}

// Manager serializes start/stop/switch across the registered games so at
// most one is ever running at a time. The zero value is not usable — build
// one with NewManager.
type Manager struct {
	mu       sync.Mutex
	registry *games.Registry
	docker   *dockerctl.Client

	// StopPollInterval/StopPollTimeout bound how long ConfirmSwitch waits
	// for the stopped game to actually report offline before starting the
	// next one. Zero means use the package defaults; overridable for tests.
	StopPollInterval time.Duration
	StopPollTimeout  time.Duration
}

func NewManager(registry *games.Registry, docker *dockerctl.Client) *Manager {
	return &Manager{registry: registry, docker: docker}
}

func (m *Manager) pollInterval() time.Duration {
	if m.StopPollInterval > 0 {
		return m.StopPollInterval
	}
	return defaultStopPollInterval
}

func (m *Manager) pollTimeout() time.Duration {
	if m.StopPollTimeout > 0 {
		return m.StopPollTimeout
	}
	return defaultStopPollTimeout
}

// ActiveGame returns the ID of the first registered game found to be
// online or starting, if any. A game whose status can't be determined
// right now is treated as not active rather than erroring the whole scan.
func (m *Manager) ActiveGame(ctx context.Context) (string, bool) {
	for _, d := range m.registry.All() {
		if d.Status == nil {
			continue
		}
		status, err := d.Status.Check(ctx, d.ContainerName)
		if err != nil {
			continue
		}
		if status == games.StatusOnline || status == games.StatusStarting {
			return d.ID, true
		}
	}
	return "", false
}

// RequestStart starts id, refusing with a *ConflictError if a different
// game is already active. Starting the already-active game is not a
// conflict. Safe to call concurrently: only one caller's
// start/stop/switch runs at a time.
func (m *Manager) RequestStart(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.startLocked(ctx, id)
}

func (m *Manager) startLocked(ctx context.Context, id string) error {
	target, ok := m.registry.Get(id)
	if !ok {
		return fmt.Errorf("exclusivity: unknown game %q", id)
	}
	if active, ok := m.ActiveGame(ctx); ok && active != id {
		return &ConflictError{Active: active}
	}
	return m.docker.Start(ctx, target.DockerTarget())
}

// Stop stops id. No conflict is possible — stopping is always safe.
func (m *Manager) Stop(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked(ctx, id)
}

func (m *Manager) stopLocked(ctx context.Context, id string) error {
	d, ok := m.registry.Get(id)
	if !ok {
		return fmt.Errorf("exclusivity: unknown game %q", id)
	}
	return m.docker.Stop(ctx, d.ContainerName)
}

// ConfirmSwitch stops `from`, waits (bounded) for it to actually report
// offline, then starts `to`. Serialized by the same lock as
// RequestStart/Stop so two concurrent requests (two browser tabs) can't
// race into both containers running at once.
func (m *Manager) ConfirmSwitch(ctx context.Context, from, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	fromDef, ok := m.registry.Get(from)
	if !ok {
		return fmt.Errorf("exclusivity: unknown game %q", from)
	}
	if err := m.stopLocked(ctx, from); err != nil {
		return fmt.Errorf("exclusivity: stop %s: %w", from, err)
	}
	if err := m.waitOffline(ctx, fromDef); err != nil {
		return err
	}
	return m.startLocked(ctx, to)
}

func (m *Manager) waitOffline(ctx context.Context, d games.GameDef) error {
	if d.Status == nil {
		return nil
	}
	deadline := time.Now().Add(m.pollTimeout())
	ticker := time.NewTicker(m.pollInterval())
	defer ticker.Stop()

	for {
		status, err := d.Status.Check(ctx, d.ContainerName)
		if err == nil && status == games.StatusOffline {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("exclusivity: timed out waiting for %s to stop", d.ID)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
