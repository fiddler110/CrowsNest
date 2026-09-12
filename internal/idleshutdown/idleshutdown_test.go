package idleshutdown

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
)

// fakeStatus reports a fixed Status/error, optionally switching to a
// different one after a number of calls (to simulate a status transition
// across ticks).
type fakeStatus struct {
	status games.Status
	err    error
}

func (f *fakeStatus) Check(ctx context.Context, name string) (games.Status, error) {
	return f.status, f.err
}

// fakePlayers reports a fixed count/ok pair, mutable between ticks.
type fakePlayers struct {
	count int
	ok    bool
}

func (f *fakePlayers) PlayerCount(ctx context.Context) (int, []string, bool) {
	return f.count, nil, f.ok
}

type fakeStopper struct {
	stopped []string
}

func (f *fakeStopper) Stop(ctx context.Context, id string) error {
	f.stopped = append(f.stopped, id)
	return nil
}

// newTestManager builds a Manager around a single game's fake strategies,
// with a controllable clock (advance via *clock = clock.Add(...)).
func newTestManager(t *testing.T, status *fakeStatus, players *fakePlayers, idleDuration time.Duration) (*Manager, *fakeStopper, *time.Time) {
	t.Helper()
	def := games.GameDef{ID: "windrose", DisplayName: "windrose", ContainerName: "windrose", Status: status}
	if players != nil {
		def.Players = players
	}
	registry, err := games.NewRegistry([]games.GameDef{def})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	stopper := &fakeStopper{}
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := New(registry, stopper, idleDuration, time.Minute)
	m.Now = func() time.Time { return clock }
	return m, stopper, &clock
}

func TestTick_SeedsGraceOnTransitionToOnline(t *testing.T) {
	status := &fakeStatus{status: games.StatusOnline}
	players := &fakePlayers{count: 0, ok: true}
	m, stopper, clock := newTestManager(t, status, players, 15*time.Minute)

	m.Tick(context.Background())
	if len(stopper.stopped) != 0 {
		t.Fatalf("stopped = %v, want none on the first tick a game is seen online", stopper.stopped)
	}

	*clock = clock.Add(20 * time.Minute)
	m.Tick(context.Background())
	if len(stopper.stopped) != 1 || stopper.stopped[0] != "windrose" {
		t.Fatalf("stopped = %v, want [windrose] once idle past the grace period", stopper.stopped)
	}
}

func TestTick_NeverStopsOnUndeterminablePlayerCount(t *testing.T) {
	status := &fakeStatus{status: games.StatusOnline}
	players := &fakePlayers{ok: false}
	m, stopper, clock := newTestManager(t, status, players, 15*time.Minute)

	m.Tick(context.Background()) // seeds grace
	for i := 0; i < 10; i++ {
		*clock = clock.Add(time.Hour)
		m.Tick(context.Background())
	}
	if len(stopper.stopped) != 0 {
		t.Fatalf("stopped = %v, want none when player count is never determinable", stopper.stopped)
	}
}

func TestTick_ResetsGraceWhenPlayersReturn(t *testing.T) {
	status := &fakeStatus{status: games.StatusOnline}
	players := &fakePlayers{count: 0, ok: true}
	m, stopper, clock := newTestManager(t, status, players, 15*time.Minute)

	m.Tick(context.Background()) // seeds grace at t=0

	*clock = clock.Add(10 * time.Minute)
	players.count = 3
	m.Tick(context.Background()) // players present -> resets the clock to t=10m

	*clock = clock.Add(10 * time.Minute) // t=20m, only 10m since the reset
	players.count = 0
	m.Tick(context.Background())
	if len(stopper.stopped) != 0 {
		t.Fatalf("stopped = %v, want none — only 10m elapsed since players were last seen", stopper.stopped)
	}

	*clock = clock.Add(10 * time.Minute) // t=30m, 20m since the reset
	m.Tick(context.Background())
	if len(stopper.stopped) != 1 {
		t.Fatalf("stopped = %v, want [windrose] once 15m have passed since players were last seen", stopper.stopped)
	}
}

func TestTick_NoPlayerCounterNeverStops(t *testing.T) {
	status := &fakeStatus{status: games.StatusOnline}
	m, stopper, clock := newTestManager(t, status, nil, 15*time.Minute)

	m.Tick(context.Background())
	*clock = clock.Add(time.Hour)
	m.Tick(context.Background())

	if len(stopper.stopped) != 0 {
		t.Fatalf("stopped = %v, want none for a game with no PlayerCounter wired", stopper.stopped)
	}
}

func TestTick_OfflineResetsGracePeriod(t *testing.T) {
	status := &fakeStatus{status: games.StatusOnline}
	players := &fakePlayers{count: 0, ok: true}
	m, stopper, clock := newTestManager(t, status, players, 15*time.Minute)

	m.Tick(context.Background()) // seeds grace at t=0

	*clock = clock.Add(20 * time.Minute)
	status.status = games.StatusOffline
	m.Tick(context.Background()) // now offline -> tracked state is dropped

	status.status = games.StatusOnline
	m.Tick(context.Background()) // back online -> should reseed, not stop instantly
	if len(stopper.stopped) != 0 {
		t.Fatalf("stopped = %v, want none — a freshly (re)started game gets a fresh grace period", stopper.stopped)
	}
}

func TestTick_StatusErrorSkipsGame(t *testing.T) {
	status := &fakeStatus{status: games.StatusUnknown, err: context.DeadlineExceeded}
	players := &fakePlayers{count: 0, ok: true}
	m, stopper, clock := newTestManager(t, status, players, 15*time.Minute)

	for i := 0; i < 5; i++ {
		*clock = clock.Add(time.Hour)
		m.Tick(context.Background())
	}
	if len(stopper.stopped) != 0 {
		t.Fatalf("stopped = %v, want none when status can't be determined", stopper.stopped)
	}
}

func TestTick_UnregisteredGamesIgnored(t *testing.T) {
	registry, err := games.NewRegistry(nil)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	stopper := &fakeStopper{}
	m := New(registry, stopper, 15*time.Minute, time.Minute)
	m.Tick(context.Background())
	if len(stopper.stopped) != 0 {
		t.Fatalf("stopped = %v, want none for an empty registry", stopper.stopped)
	}
}

type fakeNotifier struct {
	messages []string
}

func (f *fakeNotifier) Notify(ctx context.Context, message string) {
	f.messages = append(f.messages, message)
}

func TestTick_NotifiesOnStop(t *testing.T) {
	status := &fakeStatus{status: games.StatusOnline}
	players := &fakePlayers{count: 0, ok: true}
	m, stopper, clock := newTestManager(t, status, players, 15*time.Minute)
	notifier := &fakeNotifier{}
	m.Notifier = notifier

	m.Tick(context.Background()) // seeds grace
	if len(notifier.messages) != 0 {
		t.Fatalf("messages = %v, want none before the grace period elapses", notifier.messages)
	}

	*clock = clock.Add(20 * time.Minute)
	m.Tick(context.Background())
	if len(stopper.stopped) != 1 {
		t.Fatalf("stopped = %v, want [windrose]", stopper.stopped)
	}
	if len(notifier.messages) != 1 || !strings.Contains(notifier.messages[0], "windrose") {
		t.Fatalf("messages = %v, want one message naming windrose", notifier.messages)
	}
}

func TestTick_NoNotifierIsSafe(t *testing.T) {
	status := &fakeStatus{status: games.StatusOnline}
	players := &fakePlayers{count: 0, ok: true}
	m, stopper, clock := newTestManager(t, status, players, 15*time.Minute)

	m.Tick(context.Background())
	*clock = clock.Add(20 * time.Minute)
	m.Tick(context.Background()) // must not panic with Notifier left nil
	if len(stopper.stopped) != 1 {
		t.Fatalf("stopped = %v, want [windrose]", stopper.stopped)
	}
}
