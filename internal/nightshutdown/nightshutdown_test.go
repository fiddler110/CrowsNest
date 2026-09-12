package nightshutdown

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
)

type fakeStatus struct {
	status games.Status
	err    error
}

func (f *fakeStatus) Check(ctx context.Context, name string) (games.Status, error) {
	return f.status, f.err
}

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

type fakeNotifier struct {
	messages []string
}

func (f *fakeNotifier) Notify(ctx context.Context, message string) {
	f.messages = append(f.messages, message)
}

// newTestManager builds a Manager around a single night-shutdown-eligible
// game, with a controllable clock (advance via *clock = clock.Add(...)).
// The window defaults to 23:00-05:00 UTC.
func newTestManager(t *testing.T, status *fakeStatus, players *fakePlayers) (*Manager, *fakeStopper, *time.Time) {
	t.Helper()
	def := games.GameDef{
		ID: "windrose", DisplayName: "windrose", ContainerName: "windrose",
		Status: status, Players: players, NightShutdown: true,
	}
	registry, err := games.NewRegistry([]games.GameDef{def})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	stopper := &fakeStopper{}
	clock := time.Date(2026, 1, 1, 23, 30, 0, 0, time.UTC) // inside the default window
	m := New(registry, stopper, 23, 5, time.Minute, time.UTC)
	m.Now = func() time.Time { return clock }
	return m, stopper, &clock
}

func TestTick_StopsEmptyGameInWindow(t *testing.T) {
	status := &fakeStatus{status: games.StatusOnline}
	players := &fakePlayers{count: 0, ok: true}
	m, stopper, _ := newTestManager(t, status, players)
	notifier := &fakeNotifier{}
	m.Notifier = notifier

	m.Tick(context.Background())

	if len(stopper.stopped) != 1 || stopper.stopped[0] != "windrose" {
		t.Fatalf("stopped = %v, want [windrose]", stopper.stopped)
	}
	if len(notifier.messages) != 1 || !strings.Contains(notifier.messages[0], "windrose") {
		t.Fatalf("messages = %v, want one message naming windrose", notifier.messages)
	}
}

func TestTick_NoStopOutsideWindow(t *testing.T) {
	status := &fakeStatus{status: games.StatusOnline}
	players := &fakePlayers{count: 0, ok: true}
	m, stopper, clock := newTestManager(t, status, players)
	*clock = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) // outside 23:00-05:00

	m.Tick(context.Background())
	if len(stopper.stopped) != 0 {
		t.Fatalf("stopped = %v, want none outside the window", stopper.stopped)
	}
}

func TestTick_NoStopWithPlayers(t *testing.T) {
	status := &fakeStatus{status: games.StatusOnline}
	players := &fakePlayers{count: 2, ok: true}
	m, stopper, _ := newTestManager(t, status, players)

	m.Tick(context.Background())
	if len(stopper.stopped) != 0 {
		t.Fatalf("stopped = %v, want none while players are connected", stopper.stopped)
	}
}

func TestTick_NoStopWhenPlayerCountUndeterminable(t *testing.T) {
	status := &fakeStatus{status: games.StatusOnline}
	players := &fakePlayers{ok: false}
	m, stopper, _ := newTestManager(t, status, players)

	m.Tick(context.Background())
	if len(stopper.stopped) != 0 {
		t.Fatalf("stopped = %v, want none when player count can't be determined (safety)", stopper.stopped)
	}
}

func TestTick_NoStopWhenNotOnline(t *testing.T) {
	status := &fakeStatus{status: games.StatusOffline}
	players := &fakePlayers{count: 0, ok: true}
	m, stopper, _ := newTestManager(t, status, players)

	m.Tick(context.Background())
	if len(stopper.stopped) != 0 {
		t.Fatalf("stopped = %v, want none when the game isn't online", stopper.stopped)
	}
}

func TestTick_SkipsGamesOptedOut(t *testing.T) {
	status := &fakeStatus{status: games.StatusOnline}
	players := &fakePlayers{count: 0, ok: true}
	def := games.GameDef{
		ID: "palworld", DisplayName: "palworld", ContainerName: "palworld",
		Status: status, Players: players, NightShutdown: false,
	}
	registry, err := games.NewRegistry([]games.GameDef{def})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	stopper := &fakeStopper{}
	clock := time.Date(2026, 1, 1, 23, 30, 0, 0, time.UTC)
	m := New(registry, stopper, 23, 5, time.Minute, time.UTC)
	m.Now = func() time.Time { return clock }

	m.Tick(context.Background())
	if len(stopper.stopped) != 0 {
		t.Fatalf("stopped = %v, want none for a game opted out of night-shutdown", stopper.stopped)
	}
}

func TestInWindow_WrapsMidnight(t *testing.T) {
	m := &Manager{startHour: 23, endHour: 5, loc: time.UTC}
	tests := []struct {
		hour int
		want bool
	}{
		{22, false},
		{23, true},
		{0, true},
		{4, true},
		{5, false},
		{12, false},
	}
	for _, tt := range tests {
		got := m.inWindow(time.Date(2026, 1, 1, tt.hour, 0, 0, 0, time.UTC))
		if got != tt.want {
			t.Errorf("inWindow(hour=%d) = %v, want %v", tt.hour, got, tt.want)
		}
	}
}

func TestInWindow_SameDayWindow(t *testing.T) {
	m := &Manager{startHour: 9, endHour: 17, loc: time.UTC}
	tests := []struct {
		hour int
		want bool
	}{
		{8, false},
		{9, true},
		{16, true},
		{17, false},
	}
	for _, tt := range tests {
		got := m.inWindow(time.Date(2026, 1, 1, tt.hour, 0, 0, 0, time.UTC))
		if got != tt.want {
			t.Errorf("inWindow(hour=%d) = %v, want %v", tt.hour, got, tt.want)
		}
	}
}
