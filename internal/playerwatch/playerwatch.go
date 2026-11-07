// Package playerwatch announces players joining and leaving a game, by
// diffing the names its PlayerCounter reports between polls. It only speaks
// from a positive reading: an unreadable count is skipped, and the first
// reading after a game comes online just seeds the baseline, so a CrowsNest
// restart doesn't announce everyone already aboard as "joined".
package playerwatch

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/history"
)

// Notifier delivers a message; satisfied by *notify.Discord.
type Notifier interface {
	Notify(ctx context.Context, message string)
}

type state struct {
	names []string // sorted; nil when the game reports no names
	count int
}

// Watcher polls every registered game. Build with New.
type Watcher struct {
	registry *games.Registry
	notifier Notifier
	// History, when set, records a join/leave event per named player (the
	// source of playtime totals). Optional.
	History  history.Recorder
	interval time.Duration
	last     map[string]state // present only while a game is online and readable
}

// New builds a Watcher that polls every interval.
func New(registry *games.Registry, notifier Notifier, interval time.Duration) *Watcher {
	return &Watcher{registry: registry, notifier: notifier, interval: interval, last: map[string]state{}}
}

// Run polls until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Tick(ctx)
		}
	}
}

// Tick polls every game once.
func (w *Watcher) Tick(ctx context.Context) {
	for _, d := range w.registry.All() {
		w.check(ctx, d)
	}
}

func (w *Watcher) check(ctx context.Context, d games.GameDef) {
	if d.Status == nil || !games.CanCountPlayers(d) {
		return
	}
	status, err := d.Status.Check(ctx, d.ContainerName)
	if err != nil || status != games.StatusOnline {
		if err == nil { // confirmed not online: start over next time
			delete(w.last, d.ID)
		}
		return
	}
	count, names, ok := d.Players.PlayerCount(ctx)
	if !ok {
		return
	}
	cur := state{count: count}
	if len(names) > 0 {
		cur.names = slices.Clone(names)
		sort.Strings(cur.names)
		cur.count = len(cur.names)
	}
	prev, seen := w.last[d.ID]
	w.last[d.ID] = cur
	if !seen {
		return
	}

	switch {
	case cur.names != nil && (prev.names != nil || prev.count == 0):
		joined, left := diff(prev.names, cur.names)
		for _, n := range joined {
			w.record(history.KindJoin, d.ID, n)
		}
		for _, n := range left {
			w.record(history.KindLeave, d.ID, n)
		}
		if len(joined) > 0 {
			w.say(ctx, fmt.Sprintf("➡️ **%s** joined **%s** (%d online).", strings.Join(joined, ", "), d.DisplayName, cur.count))
		}
		if len(left) > 0 {
			w.say(ctx, fmt.Sprintf("⬅️ **%s** left **%s** (%d online).", strings.Join(left, ", "), d.DisplayName, cur.count))
		}
	case cur.count > prev.count:
		w.say(ctx, fmt.Sprintf("➡️ Someone joined **%s** (%d online).", d.DisplayName, cur.count))
	case cur.count < prev.count:
		w.say(ctx, fmt.Sprintf("⬅️ Someone left **%s** (%d online).", d.DisplayName, cur.count))
	}
}

func (w *Watcher) record(kind, game, player string) {
	if w.History != nil {
		w.History.Record(kind, game, player, "")
	}
}

func (w *Watcher) say(ctx context.Context, msg string) {
	if w.notifier != nil {
		w.notifier.Notify(ctx, msg)
	}
}

// diff returns the names in cur but not prev, and in prev but not cur. Both
// inputs are sorted.
func diff(prev, cur []string) (joined, left []string) {
	for _, n := range cur {
		if _, found := slices.BinarySearch(prev, n); !found {
			joined = append(joined, n)
		}
	}
	for _, n := range prev {
		if _, found := slices.BinarySearch(cur, n); !found {
			left = append(left, n)
		}
	}
	return joined, left
}
