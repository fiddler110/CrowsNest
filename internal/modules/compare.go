package modules

import (
	"context"
	"log"
	"slices"
	"sync"

	"github.com/fiddler110/crowsnest/internal/games"
)

// comparingCounter answers with primary and checks it against other, logging
// when they disagree. It is how a new player source is validated against a
// trusted one on a real server before anyone relies on it: the log line is
// the evidence, and only changes are logged, not every poll.
type comparingCounter struct {
	name           string
	primary, other games.PlayerCounter
	// namesFromOther takes display names from other, but only while it
	// agrees with primary on the count. Names must not flap between ids and
	// real names (the join/leave notices diff them), so when other lags the
	// last agreed names are kept as long as primary's players are unchanged,
	// and otherwise none are reported (the notices then say "Someone").
	namesFromOther bool

	mu        sync.Mutex
	last      bool // disagreed on the previous poll
	lastSeen  [2]int
	lastIDs   []string // primary's players when lastNames were agreed
	lastNames []string
}

func (c *comparingCounter) PlayerCount(ctx context.Context) (int, []string, bool) {
	n, names, ok := c.primary.PlayerCount(ctx)
	if !ok || c.other == nil {
		return n, names, ok
	}
	m, onames, ok2 := c.other.PlayerCount(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.namesFromOther {
		names = c.resolveNames(n, names, onames, ok2 && m == n)
	}
	if !ok2 {
		return n, names, ok
	}
	disagree := n != m
	if disagree && (!c.last || c.lastSeen != [2]int{n, m}) {
		log.Printf("%s: player count sources disagree (primary %d, other %d)", c.name, n, m)
	} else if !disagree && c.last {
		log.Printf("%s: player count sources agree again (%d)", c.name, n)
	}
	c.last, c.lastSeen = disagree, [2]int{n, m}
	return n, names, ok
}

// resolveNames picks the names to report for n players whose primary ids are
// ids; agreed says other confirmed the same count.
func (c *comparingCounter) resolveNames(n int, ids, onames []string, agreed bool) []string {
	sorted := slices.Sorted(slices.Values(ids))
	switch {
	case n == 0:
		c.lastIDs, c.lastNames = nil, nil
		return nil
	case agreed && len(onames) == n:
		c.lastIDs, c.lastNames = sorted, slices.Clone(onames)
		return c.lastNames
	case c.lastNames != nil && slices.Equal(c.lastIDs, sorted):
		return c.lastNames
	}
	return nil
}
