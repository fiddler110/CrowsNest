// Package schedule starts and stops games at set times of the week ("start
// Friday 18:00, stop Sunday 23:00"). Entries live in a small JSON file the
// admin edits from Settings. The runner checks every few seconds and fires an
// entry once in the minute it names. A time that passes while CrowsNest is
// down is not made up on restart.
package schedule

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/atomicfile"
	"github.com/fiddler110/crowsnest/internal/audit"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/history"
	"github.com/fiddler110/crowsnest/internal/statehub"
)

const (
	ActionStart = "start"
	ActionStop  = "stop"
	// MaxEntries bounds the file.
	MaxEntries = 100
)

var (
	timeRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	idRe   = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)
)

// Entry is one scheduled action.
type Entry struct {
	ID      string `json:"id"`
	Game    string `json:"game"`
	Action  string `json:"action"` // start or stop
	Days    []int  `json:"days"`   // 0 = Sunday ... 6 = Saturday
	Time    string `json:"time"`   // 24-hour HH:MM in the server's time zone
	Enabled bool   `json:"enabled"`
	// OnlyIfEmpty makes a stop wait out a busy server: it is skipped when
	// anyone is connected, or when the player count is unknown.
	OnlyIfEmpty bool `json:"only_if_empty,omitempty"`
}

// Validate checks one entry. known reports whether a game id exists.
func (e Entry) Validate(known func(string) bool) error {
	switch {
	case !idRe.MatchString(e.ID):
		return errors.New("each schedule needs an id of letters, digits, - or _")
	case !known(e.Game):
		return fmt.Errorf("%s: unknown game", e.ID)
	case e.Action != ActionStart && e.Action != ActionStop:
		return fmt.Errorf("%s: action must be start or stop", e.ID)
	case !timeRe.MatchString(e.Time):
		return fmt.Errorf("%s: time must be 24-hour HH:MM", e.ID)
	case len(e.Days) == 0 || len(e.Days) > 7:
		return fmt.Errorf("%s: pick at least one day", e.ID)
	}
	seen := map[int]bool{}
	for _, d := range e.Days {
		if d < 0 || d > 6 || seen[d] {
			return fmt.Errorf("%s: days are 0 (Sunday) to 6 (Saturday), each once", e.ID)
		}
		seen[d] = true
	}
	return nil
}

// Store keeps the entries in a JSON file.
type Store struct {
	path string
	mu   sync.Mutex
	list []Entry
}

// Open reads path; a missing file means no schedules.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	raw, err := os.ReadFile(path) // #nosec G304 -- derived from the operator's config
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("schedule: read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &s.list); err != nil {
		return nil, fmt.Errorf("schedule: parse %s: %w", path, err)
	}
	return s, nil
}

// List returns a copy of the entries.
func (s *Store) List() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, len(s.list))
	copy(out, s.list)
	return out
}

// Replace validates and saves the whole list.
func (s *Store) Replace(list []Entry, known func(string) bool) error {
	if len(list) > MaxEntries {
		return fmt.Errorf("at most %d schedules", MaxEntries)
	}
	ids := map[string]bool{}
	for i := range list {
		if err := list[i].Validate(known); err != nil {
			return err
		}
		if ids[list[i].ID] {
			return fmt.Errorf("%s: duplicate id", list[i].ID)
		}
		ids[list[i].ID] = true
		sort.Ints(list[i].Days)
	}
	out, _ := json.MarshalIndent(list, "", "  ")
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := atomicfile.Write(s.path, append(out, '\n'), 0o600); err != nil {
		return err
	}
	s.list = append([]Entry(nil), list...)
	return nil
}

// Controller starts and stops games (*exclusivity.Manager).
type Controller interface {
	RequestStart(ctx context.Context, id string) error
	RequestStop(ctx context.Context, id string) error
}

// Actor is the name the runner acts under; actionContext adds it with ActorCtx.
const Actor = "schedule"

// Runner fires due entries.
type Runner struct {
	Store    *Store
	Registry *games.Registry
	Control  Controller
	Hub      *statehub.Hub
	History  history.Recorder
	Loc      *time.Location
	// ActorCtx wraps ctx so the controller knows who acts (exclusivity.WithActor).
	ActorCtx func(ctx context.Context, name string) context.Context
	// Notify, when set, is told about a failed or skipped entry.
	Notify func(ctx context.Context, msg string)
	Now    func() time.Time

	mu    sync.Mutex
	fired map[string]string // entry id -> the minute it last fired
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Run ticks until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Tick(ctx)
		}
	}
}

// Tick fires every enabled entry that is due this minute and has not fired in it.
func (r *Runner) Tick(ctx context.Context) {
	loc := r.Loc
	if loc == nil {
		loc = time.UTC
	}
	now := r.now().In(loc)
	minute := now.Format("2006-01-02 15:04")
	hhmm := now.Format("15:04")
	for _, e := range r.Store.List() {
		if !e.Enabled || e.Time != hhmm || !hasDay(e.Days, int(now.Weekday())) {
			continue
		}
		r.mu.Lock()
		if r.fired == nil {
			r.fired = map[string]string{}
		}
		done := r.fired[e.ID] == minute
		r.fired[e.ID] = minute
		r.mu.Unlock()
		if !done {
			r.fire(ctx, e)
		}
	}
}

func hasDay(days []int, d int) bool {
	for _, x := range days {
		if x == d {
			return true
		}
	}
	return false
}

func (r *Runner) fire(ctx context.Context, e Entry) {
	d, ok := r.Registry.Get(e.Game)
	if !ok {
		return
	}
	actx := ctx
	if r.ActorCtx != nil {
		actx = r.ActorCtx(ctx, Actor)
	}
	fail := func(kind, msg string) {
		log.Printf("schedule: %s %s: %s", e.Action, e.Game, msg)
		if r.History != nil {
			r.History.Record(kind, e.Game, Actor, "scheduled "+e.Action+": "+msg)
		}
		if r.Notify != nil {
			r.Notify(ctx, fmt.Sprintf("Scheduled %s of **%s** did not happen: %s", e.Action, d.DisplayName, msg))
		}
	}
	if e.Action == ActionStart {
		if err := r.Control.RequestStart(actx, e.Game); err != nil {
			fail(history.KindStartFailed, err.Error())
			return
		}
		audit.Printf("schedule %s started %s", e.ID, e.Game)
		return
	}
	if e.OnlyIfEmpty {
		if r.Hub == nil {
			fail(history.KindStopFailed, "skipped, players could not be checked")
			return
		}
		o := r.Hub.Fresh(ctx, d)
		if o.Status != games.StatusOnline {
			return // already down
		}
		if !o.PlayersOK {
			fail(history.KindStopFailed, "skipped, the player count is unknown")
			return
		}
		if o.Count > 0 {
			fail(history.KindStopFailed, fmt.Sprintf("skipped, %d player(s) online", o.Count))
			return
		}
	}
	if err := r.Control.RequestStop(actx, e.Game); err != nil {
		fail(history.KindStopFailed, err.Error())
		return
	}
	audit.Printf("schedule %s requested stop of %s", e.ID, e.Game)
}
