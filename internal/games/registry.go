package games

import (
	"fmt"
	"sync"
)

// Registry holds one GameDef per game, keyed by ID, preserving the order
// games were added for listing. It is safe for concurrent use: games enabled
// from the dashboard are added and removed while the server runs.
type Registry struct {
	mu    sync.RWMutex
	order []string
	byID  map[string]GameDef
}

// NewRegistry builds a Registry from defs, rejecting a missing or duplicate
// ID.
func NewRegistry(defs []GameDef) (*Registry, error) {
	r := &Registry{byID: make(map[string]GameDef, len(defs))}
	for i, d := range defs {
		if err := r.Add(d); err != nil {
			return nil, fmt.Errorf("games: defs[%d]: %w", i, err)
		}
	}
	return r, nil
}

// Add registers a game at the end of the order.
func (r *Registry) Add(d GameDef) error {
	if d.ID == "" {
		return fmt.Errorf("ID is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byID[d.ID]; dup {
		return fmt.Errorf("duplicate id %q", d.ID)
	}
	r.byID[d.ID] = d
	r.order = append(r.order, d.ID)
	return nil
}

// Remove drops a game; it reports whether there was one.
func (r *Registry) Remove(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[id]; !ok {
		return false
	}
	delete(r.byID, id)
	for i, o := range r.order {
		if o == id {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
	return true
}

// Get returns the GameDef for id, if registered.
func (r *Registry) Get(id string) (GameDef, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.byID[id]
	return d, ok
}

// All returns every registered GameDef in order.
func (r *Registry) All() []GameDef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]GameDef, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.byID[id])
	}
	return out
}
