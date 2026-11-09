package modules

import (
	"context"
	"log"
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

	mu       sync.Mutex
	last     bool // disagreed on the previous poll
	lastSeen [2]int
}

func (c *comparingCounter) PlayerCount(ctx context.Context) (int, []string, bool) {
	n, names, ok := c.primary.PlayerCount(ctx)
	if !ok || c.other == nil {
		return n, names, ok
	}
	m, _, ok2 := c.other.PlayerCount(ctx)
	if !ok2 {
		return n, names, ok
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	disagree := n != m
	if disagree && (!c.last || c.lastSeen != [2]int{n, m}) {
		log.Printf("%s: player count sources disagree (primary %d, other %d)", c.name, n, m)
	} else if !disagree && c.last {
		log.Printf("%s: player count sources agree again (%d)", c.name, n)
	}
	c.last, c.lastSeen = disagree, [2]int{n, m}
	return n, names, ok
}
