package games

import "fmt"

// Registry holds one GameDef per configured game, keyed by ID, preserving
// configuration order for listing.
type Registry struct {
	order []string
	byID  map[string]GameDef
}

// NewRegistry builds a Registry from defs, rejecting a missing or duplicate
// ID.
func NewRegistry(defs []GameDef) (*Registry, error) {
	byID := make(map[string]GameDef, len(defs))
	order := make([]string, 0, len(defs))
	for i, d := range defs {
		if d.ID == "" {
			return nil, fmt.Errorf("games: defs[%d]: ID is required", i)
		}
		if _, dup := byID[d.ID]; dup {
			return nil, fmt.Errorf("games: duplicate id %q", d.ID)
		}
		byID[d.ID] = d
		order = append(order, d.ID)
	}
	return &Registry{order: order, byID: byID}, nil
}

// Get returns the GameDef for id, if registered.
func (r *Registry) Get(id string) (GameDef, bool) {
	d, ok := r.byID[id]
	return d, ok
}

// All returns every registered GameDef in configuration order.
func (r *Registry) All() []GameDef {
	out := make([]GameDef, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.byID[id])
	}
	return out
}
