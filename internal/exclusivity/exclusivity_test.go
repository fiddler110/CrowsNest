package exclusivity

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/dockerctl/dockertest"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/memadmit"
)

// newRegistry builds a registry of docker-ps-status-checked GameDefs, one
// per id.
func newRegistry(t *testing.T, docker *dockerctl.Client, ids ...string) *games.Registry {
	t.Helper()
	defs := make([]games.GameDef, len(ids))
	for i, id := range ids {
		defs[i] = games.GameDef{
			ID:            id,
			DisplayName:   id,
			ContainerName: id,
			Status:        &games.DockerStatusChecker{Docker: docker},
			Players:       games.UnknownPlayerCounter{},
		}
	}
	r, err := games.NewRegistry(defs)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	return r
}

// newTestManager is NewManager plus a cleanup that waits for background
// starts, so none outlive the test (and its fake docker's temp dir).
func newTestManager(t *testing.T, reg *games.Registry, docker *dockerctl.Client) *Manager {
	t.Helper()
	m := NewManager(reg, docker)
	t.Cleanup(m.Wait)
	return m
}

// fakeEngine is an engine holding the containers in existing (stopped) and running (up).
func fakeEngine(t *testing.T, existing, running []string) (*dockertest.Fake, *dockerctl.Client) {
	t.Helper()
	f := dockertest.New(t)
	for _, n := range existing {
		f.Add(n, false)
	}
	for _, n := range running {
		f.Add(n, true)
	}
	return f, f.Client()
}

func newStaticFakeDocker(t *testing.T, existing, running []string) *dockerctl.Client {
	t.Helper()
	_, c := fakeEngine(t, existing, running)
	return c
}

func newStatefulFakeDocker(t *testing.T, existing, runningInitially []string) *dockerctl.Client {
	t.Helper()
	_, c := fakeEngine(t, existing, runningInitially)
	return c
}

func TestActiveGame_None(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, nil)
	registry := newRegistry(t, docker, "windrose", "valheim")
	mgr := newTestManager(t, registry, docker)

	if _, ok, err := mgr.ActiveGame(context.Background()); ok || err != nil {
		t.Fatalf("ActiveGame() = (ok=%v, err=%v), want (false, nil) when nothing is running", ok, err)
	}
}

func TestActiveGame_Found(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, []string{"valheim"})
	registry := newRegistry(t, docker, "windrose", "valheim", "palworld")
	mgr := newTestManager(t, registry, docker)

	active, ok, err := mgr.ActiveGame(context.Background())
	if err != nil || !ok || active != "valheim" {
		t.Fatalf("ActiveGame() = (%q, %v, %v), want (valheim, true, nil)", active, ok, err)
	}
}

// newFailingFakeDocker is an engine that answers every request with a 500: a daemon or socket-proxy hiccup.
func newFailingFakeDocker(t *testing.T) *dockerctl.Client {
	t.Helper()
	f := dockertest.New(t)
	f.Down(true)
	return f.Client()
}

func TestActiveGame_StatusCheckError(t *testing.T) {
	docker := newFailingFakeDocker(t)
	registry := newRegistry(t, docker, "windrose", "valheim")
	mgr := newTestManager(t, registry, docker)

	if _, ok, err := mgr.ActiveGame(context.Background()); ok || err == nil {
		t.Fatalf("ActiveGame() = (ok=%v, err=%v), want (false, non-nil) when a status check errors", ok, err)
	}
}

// TestRequestStart_FailsClosedOnStatusCheckError guards against
// ActiveGame's error being silently treated as "nothing is active": if a
// game's status can't be determined, RequestStart must refuse to start
// anything rather than risk two game servers running at once.
func TestRequestStart_FailsClosedOnStatusCheckError(t *testing.T) {
	docker := newFailingFakeDocker(t)
	registry := newRegistry(t, docker, "windrose", "valheim")
	mgr := newTestManager(t, registry, docker)

	if err := mgr.RequestStart(context.Background(), "windrose"); err == nil {
		t.Fatal("RequestStart() error = nil, want error when a status check fails instead of silently starting")
	}
}

func TestRequestStart_NoConflict(t *testing.T) {
	docker := newStaticFakeDocker(t, []string{"windrose"}, nil)
	registry := newRegistry(t, docker, "windrose")
	mgr := newTestManager(t, registry, docker)

	if err := mgr.RequestStart(context.Background(), "windrose"); err != nil {
		t.Fatalf("RequestStart() error = %v", err)
	}
}

func TestRequestStart_Conflict(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, []string{"valheim"})
	registry := newRegistry(t, docker, "valheim", "palworld")
	mgr := newTestManager(t, registry, docker)

	err := mgr.RequestStart(context.Background(), "palworld")
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("RequestStart() error = %v, want *ConflictError", err)
	}
	if conflict.Active != "valheim" {
		t.Fatalf("ConflictError.Active = %q, want valheim", conflict.Active)
	}
}

func TestRequestStart_AlreadyActiveIsNotAConflict(t *testing.T) {
	docker := newStaticFakeDocker(t, []string{"windrose"}, []string{"windrose"})
	registry := newRegistry(t, docker, "windrose")
	mgr := newTestManager(t, registry, docker)

	if err := mgr.RequestStart(context.Background(), "windrose"); err != nil {
		t.Fatalf("RequestStart() error = %v, want nil (restarting the already-active game is not a conflict)", err)
	}
}

func TestRequestStart_UnknownGame(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, nil)
	registry := newRegistry(t, docker)
	mgr := newTestManager(t, registry, docker)

	if err := mgr.RequestStart(context.Background(), "ghost"); err == nil {
		t.Fatal("RequestStart() error = nil, want error for an unregistered game")
	}
}

func TestStop(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, []string{"windrose"})
	registry := newRegistry(t, docker, "windrose")
	mgr := newTestManager(t, registry, docker)

	if err := mgr.Stop(context.Background(), "windrose"); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestConfirmSwitch(t *testing.T) {
	docker := newStatefulFakeDocker(t, []string{"palworld"}, []string{"valheim"})
	registry := newRegistry(t, docker, "windrose", "valheim", "palworld")
	mgr := newTestManager(t, registry, docker)
	mgr.StopPollInterval = time.Millisecond
	mgr.StopPollTimeout = time.Second

	if err := mgr.ConfirmSwitch(context.Background(), "valheim", "palworld"); err != nil {
		t.Fatalf("ConfirmSwitch() error = %v", err)
	}

	active, ok, err := mgr.ActiveGame(context.Background())
	if err != nil || !ok || active != "palworld" {
		t.Fatalf("ActiveGame() after switch = (%q, %v, %v), want (palworld, true, nil)", active, ok, err)
	}
}

func TestConfirmSwitch_TimesOutIfNeverStops(t *testing.T) {
	f, docker := fakeEngine(t, nil, []string{"stuck-game"})
	f.Stuck("stuck-game")
	registry := newRegistry(t, docker, "stuck-game", "other")
	mgr := newTestManager(t, registry, docker)
	mgr.StopPollInterval = time.Millisecond
	mgr.StopPollTimeout = 20 * time.Millisecond

	err := mgr.ConfirmSwitch(context.Background(), "stuck-game", "other")
	if err == nil {
		t.Fatal("ConfirmSwitch() error = nil, want a timeout error when the source game never reports offline")
	}
}

func TestConfirmSwitch_UnknownSource(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, nil)
	registry := newRegistry(t, docker, "other")
	mgr := newTestManager(t, registry, docker)

	if err := mgr.ConfirmSwitch(context.Background(), "ghost", "other"); err == nil {
		t.Fatal("ConfirmSwitch() error = nil, want error for an unregistered source game")
	}
}

func TestRequestStart_RestartCooldown(t *testing.T) {
	f, docker := fakeEngine(t, []string{"a"}, nil)
	reg := newRegistry(t, docker, "a")
	def, _ := reg.Get("a")
	def.RestartCooldown = time.Hour
	reg, err := games.NewRegistry([]games.GameDef{def})
	if err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, reg, docker)

	if err := m.RequestStart(context.Background(), "a"); err != nil {
		t.Fatalf("first start (never stopped) = %v, want nil", err)
	}
	if err := m.Stop(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	var cd *CooldownError
	if err := m.RequestStart(context.Background(), "a"); !errors.As(err, &cd) {
		t.Fatalf("start right after stop = %v, want *CooldownError", err)
	}
	if cd.Remaining <= 0 || cd.Remaining > time.Hour {
		t.Errorf("Remaining = %v, want within (0, 1h]", cd.Remaining)
	}

	m.lastStop["a"] = time.Now().Add(-2 * time.Hour)
	f.Add("a", false).Finished = time.Now().Add(-2 * time.Hour) // the engine's own record agrees
	if err := m.RequestStart(context.Background(), "a"); err != nil {
		t.Fatalf("start after cooldown elapsed = %v, want nil", err)
	}
}

func TestRequestStart_MaxActive(t *testing.T) {
	docker := newStaticFakeDocker(t, []string{"a", "b", "c"}, []string{"a"})
	reg := newRegistry(t, docker, "a", "b", "c")

	// Default (1): b is refused while a runs.
	var conflict *ConflictError
	if err := newTestManager(t, reg, docker).RequestStart(context.Background(), "b"); !errors.As(err, &conflict) || conflict.Active != "a" {
		t.Fatalf("default limit: RequestStart(b) = %v, want conflict with a", err)
	}

	// Limit 2: b fits alongside a.
	m := newTestManager(t, reg, docker)
	m.MaxActive = 2
	if err := m.RequestStart(context.Background(), "b"); err != nil {
		t.Fatalf("limit 2: RequestStart(b) = %v, want nil", err)
	}

	// Limit 2 with a and b both running: c is refused, listing both.
	docker2 := newStaticFakeDocker(t, []string{"a", "b", "c"}, []string{"a", "b"})
	m2 := newTestManager(t, newRegistry(t, docker2, "a", "b", "c"), docker2)
	m2.MaxActive = 2
	if err := m2.RequestStart(context.Background(), "c"); !errors.As(err, &conflict) || len(conflict.All) != 2 {
		t.Fatalf("limit 2 full: RequestStart(c) = %v, want conflict listing 2 games", err)
	}
}

// A start that is still in flight (e.g. pulling an image, container not
// created yet) must count toward the limit, or a second game could start
// alongside it.
func TestRequestStart_PendingStartCountsAsActive(t *testing.T) {
	f, docker := fakeEngine(t, []string{"a", "b"}, nil)
	f.OnStart = func(ctx context.Context, _ string) (int, string) { sleepCtx(ctx, 2*time.Second); return 0, "" }
	reg := newRegistry(t, docker, "a", "b")
	m := newTestManager(t, reg, docker)
	defer m.Wait()

	if err := m.RequestStart(context.Background(), "a"); err != nil {
		t.Fatalf("RequestStart(a) = %v", err)
	}
	if !m.Starting("a") {
		t.Fatal("Starting(a) = false right after an accepted start")
	}
	var conflict *ConflictError
	if err := m.RequestStart(context.Background(), "b"); !errors.As(err, &conflict) || conflict.Active != "a" {
		t.Fatalf("RequestStart(b) while a is still starting = %v, want conflict with a", err)
	}
	// Starting the in-flight game again is accepted and doesn't stack.
	if err := m.RequestStart(context.Background(), "a"); err != nil {
		t.Fatalf("second RequestStart(a) = %v, want nil", err)
	}
	if err := m.Stop(context.Background(), "a"); err != nil {
		t.Fatalf("Stop(a) = %v", err)
	}
}

// The background start must not be tied to the caller's context: a
// request that ends (tab closed, proxy timeout) must not kill the start.
func TestRequestStart_SurvivesCallerContextCancel(t *testing.T) {
	f, docker := fakeEngine(t, []string{"a"}, nil)
	f.OnStart = func(_ context.Context, _ string) (int, string) { time.Sleep(300 * time.Millisecond); return 0, "" }
	m := newTestManager(t, newRegistry(t, docker, "a"), docker)

	ctx, cancel := context.WithCancel(context.Background())
	if err := m.RequestStart(ctx, "a"); err != nil {
		t.Fatalf("RequestStart = %v", err)
	}
	cancel()
	m.Wait()

	if !f.Running("a") {
		t.Fatal("start did not complete after the caller's context was cancelled")
	}
	if r, ok := m.LastStart("a"); !ok || r.Err != "" {
		t.Fatalf("LastStart(a) = %+v, %v, want a successful result", r, ok)
	}
}

func TestRequestStart_FailureIsRecorded(t *testing.T) {
	f, docker := fakeEngine(t, []string{"a"}, nil)
	f.OnStart = func(context.Context, string) (int, string) { return 500, "boom: no such image" }
	m := newTestManager(t, newRegistry(t, docker, "a"), docker)
	if err := m.RequestStart(context.Background(), "a"); err != nil {
		t.Fatalf("RequestStart = %v (failure should be async)", err)
	}
	m.Wait()
	r, ok := m.LastStart("a")
	if !ok || r.Err == "" || strings.Contains(r.Err, "boom") || !strings.Contains(r.Detail, "boom") {
		t.Fatalf("LastStart(a) = %+v, %v, want a public Err and the raw docker error in Detail", r, ok)
	}
	if m.Starting("a") {
		t.Fatal("Starting(a) still true after the start failed")
	}
}

// Stop on a game whose start is still in flight cancels that start before
// stopping, so the start can't bring the container up afterwards.
func TestStop_CancelsPendingStart(t *testing.T) {
	f, docker := fakeEngine(t, []string{"a"}, nil)
	f.OnStart = func(ctx context.Context, _ string) (int, string) { sleepCtx(ctx, 30*time.Second); return 0, "" }
	m := newTestManager(t, newRegistry(t, docker, "a"), docker)
	if err := m.RequestStart(context.Background(), "a"); err != nil {
		t.Fatalf("RequestStart = %v", err)
	}
	began := time.Now()
	if err := m.Stop(context.Background(), "a"); err != nil {
		t.Fatalf("Stop = %v", err)
	}
	m.Wait()
	if time.Since(began) > 10*time.Second {
		t.Fatalf("Stop took %s; the pending start was not cancelled", time.Since(began))
	}
	if m.Starting("a") {
		t.Fatal("Starting(a) still true after Stop")
	}
	if r, _ := m.LastStart("a"); r.Err != "" {
		t.Fatalf("cancelled start recorded as a failure: %q", r.Err)
	}
}

// The restart cooldown also counts stops CrowsNest didn't make (a crash,
// an external docker stop, or one from before a CrowsNest restart), read
// from the container's State.FinishedAt.
func TestRequestStart_CooldownFromFinishedAt(t *testing.T) {
	f, docker := fakeEngine(t, []string{"a"}, nil)
	f.Add("a", false).Finished = time.Now().Add(-5 * time.Second)
	def := games.GameDef{ID: "a", DisplayName: "a", ContainerName: "a",
		Status: &games.DockerStatusChecker{Docker: docker}, RestartCooldown: time.Minute}
	reg, err := games.NewRegistry([]games.GameDef{def})
	if err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, reg, docker)
	defer m.Wait()

	var cd *CooldownError
	if err := m.RequestStart(context.Background(), "a"); !errors.As(err, &cd) {
		t.Fatalf("start 5s after an external stop = %v, want *CooldownError", err)
	}

	f.Add("a", false).Finished = time.Now().Add(-2 * time.Minute)
	if err := m.RequestStart(context.Background(), "a"); err != nil {
		t.Fatalf("start after the cooldown elapsed = %v, want nil", err)
	}
}

// Stop on a game whose container does not exist (its start failed, or it was never created) is a successful
// stop, and the failed start is not left marked as starting.
func TestStop_BeforeContainerExists(t *testing.T) {
	_, docker := fakeEngine(t, nil, nil)
	def := games.GameDef{ID: "a", DisplayName: "a", ContainerName: "a",
		Status: &games.DockerStatusChecker{Docker: docker}}
	reg, err := games.NewRegistry([]games.GameDef{def})
	if err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, reg, docker)
	if err := m.RequestStart(context.Background(), "a"); err != nil {
		t.Fatalf("RequestStart = %v", err)
	}
	if err := m.Stop(context.Background(), "a"); err != nil {
		t.Fatalf("Stop with no container = %v, want nil", err)
	}
	m.Wait()
	if m.Starting("a") {
		t.Fatal("Starting(a) still true after Stop")
	}
}

// recordingNotifier collects messages; safe for the manager's notifier
// goroutines.
type recordingNotifier struct {
	mu   sync.Mutex
	msgs []string
}

func (r *recordingNotifier) Notify(_ context.Context, message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, message)
}

func (r *recordingNotifier) messages() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.msgs...)
}

func TestNotify_StartByUser(t *testing.T) {
	docker := newStaticFakeDocker(t, []string{"windrose"}, nil)
	m := newTestManager(t, newRegistry(t, docker, "windrose"), docker)
	n := &recordingNotifier{}
	m.Notifier = n

	if err := m.RequestStart(WithActor(context.Background(), "alice"), "windrose"); err != nil {
		t.Fatalf("RequestStart() error = %v", err)
	}
	m.Wait()
	got := n.messages()
	if len(got) != 1 || !strings.Contains(got[0], "**windrose** is starting (requested by alice)") {
		t.Fatalf("messages = %q, want one start message naming alice", got)
	}
}

func TestNotify_StopOnlyWithActor(t *testing.T) {
	docker := newStaticFakeDocker(t, nil, []string{"windrose"})
	m := newTestManager(t, newRegistry(t, docker, "windrose"), docker)
	n := &recordingNotifier{}
	m.Notifier = n

	// Auto-stops (idle/night) call Stop with no actor and notify themselves.
	if err := m.Stop(context.Background(), "windrose"); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	m.Wait()
	if got := n.messages(); len(got) != 0 {
		t.Fatalf("messages after actor-less Stop = %q, want none", got)
	}

	if err := m.Stop(WithActor(context.Background(), "bob"), "windrose"); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	m.Wait()
	got := n.messages()
	if len(got) != 1 || !strings.Contains(got[0], "stopped by bob") {
		t.Fatalf("messages = %q, want one stop message naming bob", got)
	}
}

func TestNotify_SwitchIsOneMessage(t *testing.T) {
	docker := newStatefulFakeDocker(t, []string{"palworld"}, []string{"valheim"})
	m := newTestManager(t, newRegistry(t, docker, "windrose", "valheim", "palworld"), docker)
	m.StopPollInterval = time.Millisecond
	m.StopPollTimeout = time.Second
	n := &recordingNotifier{}
	m.Notifier = n

	if err := m.ConfirmSwitch(WithActor(context.Background(), "carol"), "valheim", "palworld"); err != nil {
		t.Fatalf("ConfirmSwitch() error = %v", err)
	}
	m.Wait()
	got := n.messages()
	if len(got) != 1 || !strings.Contains(got[0], "carol switched from **valheim** to **palworld**") {
		t.Fatalf("messages = %q, want exactly one switch message", got)
	}
}

func TestNotify_StartFailureIsTrimmed(t *testing.T) {
	f, docker := fakeEngine(t, []string{"a"}, nil)
	f.OnStart = func(context.Context, string) (int, string) {
		return 500, strings.Repeat("noise line\n", 100) + "boom: no such image"
	}
	m := newTestManager(t, newRegistry(t, docker, "a"), docker)
	n := &recordingNotifier{}
	m.Notifier = n

	if err := m.RequestStart(context.Background(), "a"); err != nil {
		t.Fatalf("RequestStart() error = %v", err)
	}
	m.Wait()
	got := n.messages()
	if len(got) != 1 || !strings.Contains(got[0], "failed to start") || strings.Contains(got[0], "boom") || strings.Contains(got[0], "noise") {
		t.Fatalf("messages = %q, want one failure message without raw docker output", got)
	}
	if strings.Contains(got[0], "\n") || len(got[0]) > 400 {
		t.Fatalf("failure message not trimmed to one short line (len %d): %q", len(got[0]), got[0])
	}
}

// A slow `docker stop` must not block the decision lock: other requests
// return promptly while it runs, and RequestStop itself returns at once.
func TestRequestStop_IsAsyncAndDoesNotBlockOtherGames(t *testing.T) {
	f, docker := fakeEngine(t, nil, []string{"a"})
	f.OnStop = func(ctx context.Context, _ string) (int, string) { sleepCtx(ctx, time.Second); return 0, "" }
	reg := newRegistry(t, docker, "a", "b")
	m := newTestManager(t, reg, docker)

	began := time.Now()
	if err := m.RequestStop(context.Background(), "a"); err != nil {
		t.Fatalf("RequestStop = %v", err)
	}
	if d := time.Since(began); d > 500*time.Millisecond {
		t.Fatalf("RequestStop took %s, want it to return immediately", d)
	}
	if !m.Stopping("a") {
		t.Fatal("Stopping(a) = false right after an accepted stop")
	}
	// The decision lock is free: a start of the stopping game is refused as busy.
	var busy *BusyError
	if err := m.RequestStart(context.Background(), "a"); !errors.As(err, &busy) {
		t.Fatalf("RequestStart(a) while stopping = %v, want BusyError", err)
	}
	m.Wait()
	if m.Stopping("a") {
		t.Fatal("Stopping(a) still true after the stop finished")
	}
}

func TestRequestStop_FailureIsRecorded(t *testing.T) {
	f, docker := fakeEngine(t, nil, []string{"a"})
	f.OnStop = func(context.Context, string) (int, string) { return 500, "boom" }
	reg := newRegistry(t, docker, "a")
	m := newTestManager(t, reg, docker)
	if err := m.RequestStop(context.Background(), "a"); err != nil {
		t.Fatalf("RequestStop = %v", err)
	}
	m.Wait()
	res, ok := m.LastStart("a")
	if !ok || !strings.HasPrefix(res.Err, "stop failed:") || strings.Contains(res.Err, "boom") || !strings.Contains(res.Detail, "boom") {
		t.Fatalf("LastStart(a) = %+v, %v; want a recorded stop failure", res, ok)
	}
}

// A switch outlives the request that asked for it, and while it runs the
// target is reserved so a third game can't take its slot.
func TestRequestSwitch_AsyncAndReservesTarget(t *testing.T) {
	docker := newStatefulFakeDocker(t, []string{"a", "b", "c"}, []string{"a"})
	reg := newRegistry(t, docker, "a", "b", "c")
	m := newTestManager(t, reg, docker)
	m.StopPollInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	if err := m.RequestSwitch(ctx, "a", "b"); err != nil {
		t.Fatalf("RequestSwitch = %v", err)
	}
	cancel() // the HTTP request is gone; the switch must carry on
	m.Wait()

	active, err := m.ActiveGames(context.Background())
	if err != nil || len(active) != 1 || active[0] != "b" {
		t.Fatalf("ActiveGames after switch = %v, %v; want [b]", active, err)
	}
}

func TestRequestSwitch_ReservationBlocksThirdGame(t *testing.T) {
	f, docker := fakeEngine(t, nil, []string{"a"})
	f.OnStop = func(ctx context.Context, _ string) (int, string) { sleepCtx(ctx, time.Second); return 0, "" }
	reg := newRegistry(t, docker, "a", "b", "c")
	m := newTestManager(t, reg, docker)
	m.StopPollInterval, m.StopPollTimeout = 10*time.Millisecond, 100*time.Millisecond
	if err := m.RequestSwitch(context.Background(), "a", "b"); err != nil {
		t.Fatalf("RequestSwitch = %v", err)
	}
	var conflict *ConflictError
	if err := m.RequestStart(context.Background(), "c"); !errors.As(err, &conflict) {
		t.Fatalf("RequestStart(c) during switch a->b = %v, want conflict", err)
	}
	m.Wait()
}

type fakePreStop struct {
	calls int
	err   error
}

func (f *fakePreStop) PrepareStop(context.Context) error { f.calls++; return f.err }

// The pre-stop hook runs before docker stop when the game is up, and its
// failure never prevents the stop.
func TestStop_RunsPreStopHookAndIgnoresItsFailure(t *testing.T) {
	docker := newStatefulFakeDocker(t, []string{"a"}, []string{"a"})
	reg := newRegistry(t, docker, "a")
	hook := &fakePreStop{err: errors.New("api down")}
	d, _ := reg.Get("a")
	d.PreStop = hook
	reg, _ = games.NewRegistry([]games.GameDef{d})
	m := newTestManager(t, reg, docker)

	if err := m.Stop(context.Background(), "a"); err != nil {
		t.Fatalf("Stop = %v, want success despite the hook failing", err)
	}
	if hook.calls != 1 {
		t.Fatalf("hook ran %d times, want 1", hook.calls)
	}
	// Not running -> hook skipped.
	if err := m.Stop(context.Background(), "a"); err != nil {
		t.Fatalf("second Stop = %v", err)
	}
	if hook.calls != 1 {
		t.Fatalf("hook ran for a game that was already down (%d calls)", hook.calls)
	}
}

type recorded struct{ kind, game, actor, detail string }
type fakeRecorder struct {
	mu     sync.Mutex
	events []recorded
}

func (f *fakeRecorder) Record(kind, game, actor, detail string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, recorded{kind, game, actor, detail})
}

func (f *fakeRecorder) kinds() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.events {
		out = append(out, e.kind+":"+e.game+":"+e.actor)
	}
	return strings.Join(out, ",")
}

func TestHistory_RecordsUserActionsButNotAutoStops(t *testing.T) {
	docker := newStatefulFakeDocker(t, []string{"a", "b"}, []string{"a"})
	reg := newRegistry(t, docker, "a", "b")
	m := newTestManager(t, reg, docker)
	m.StopPollInterval = 10 * time.Millisecond
	rec := &fakeRecorder{}
	m.History = rec

	if err := m.Stop(context.Background(), "a"); err != nil { // auto-stop style: no actor
		t.Fatal(err)
	}
	if got := rec.kinds(); got != "" {
		t.Fatalf("an actor-less stop recorded %q; idle/night record their own", got)
	}
	if err := m.RequestStart(WithActor(context.Background(), "alex"), "a"); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if err := m.ConfirmSwitch(WithActor(context.Background(), "alex"), "a", "b"); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if got, want := rec.kinds(), "start:a:alex,stop:a:alex,start:b:alex"; got != want {
		t.Fatalf("recorded %q, want %q", got, want)
	}
}

type fakeBackups struct {
	calls []string
	err   error
}

func (f *fakeBackups) RunBackup(_ context.Context, d games.GameDef, actor string) error {
	f.calls = append(f.calls, d.ID+":"+actor)
	return f.err
}

func TestStop_BacksUpBeforeStopWhenConfigured(t *testing.T) {
	docker := newStatefulFakeDocker(t, []string{"a", "b"}, []string{"a", "b"})
	reg := newRegistry(t, docker, "a", "b")
	a, _ := reg.Get("a")
	a.Backup = &games.BackupSpec{Exec: []string{"backup"}, BeforeStop: true}
	b, _ := reg.Get("b")
	b.Backup = &games.BackupSpec{Exec: []string{"backup"}} // configured, but not before_stop
	reg, _ = games.NewRegistry([]games.GameDef{a, b})
	m := newTestManager(t, reg, docker)
	fb := &fakeBackups{err: errors.New("disk full")}
	m.Backups = fb

	if err := m.Stop(context.Background(), "a"); err != nil {
		t.Fatalf("Stop = %v, want success even though the backup failed", err)
	}
	if err := m.Stop(context.Background(), "b"); err != nil {
		t.Fatal(err)
	}
	if len(fb.calls) != 1 || fb.calls[0] != "a:" {
		t.Fatalf("backup calls = %v, want only a (before_stop)", fb.calls)
	}
}

// A switch to a target still in its restart cooldown must be refused up
// front; stopping `from` first would leave nothing running.
func TestRequestSwitch_TargetInCooldownStopsNothing(t *testing.T) {
	docker := newStaticFakeDocker(t, []string{"a", "b"}, []string{"a"})
	reg := newRegistry(t, docker, "a", "b")
	def, _ := reg.Get("b")
	def.RestartCooldown = time.Hour
	adef, _ := reg.Get("a")
	reg, err := games.NewRegistry([]games.GameDef{adef, def})
	if err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, reg, docker)
	m.lastStop["b"] = time.Now()

	var cd *CooldownError
	if err := m.RequestSwitch(context.Background(), "a", "b"); !errors.As(err, &cd) {
		t.Fatalf("RequestSwitch = %v, want *CooldownError", err)
	}
	if m.Stopping("a") {
		t.Fatal("source was stopped despite the refused switch")
	}
	if _, reserved := m.incoming["b"]; reserved {
		t.Fatal("target left reserved after refusal")
	}
}

func TestPublicFailure(t *testing.T) {
	if got := publicFailure("stop failed: ", errors.New("secret path /x")); strings.Contains(got, "secret") || !strings.HasPrefix(got, "stop failed: ") {
		t.Fatalf("publicFailure leaked or lost prefix: %q", got)
	}
	cd := &CooldownError{Game: "a", Remaining: time.Minute}
	if got := publicFailure("", cd); got != cd.Error() {
		t.Fatalf("cooldown text changed: %q", got)
	}
}

func newBudget(avail uint64, need map[string]uint64) *memadmit.Budget {
	b := memadmit.New("")
	b.Available = func() uint64 { return avail }
	b.Declared = func(id string) uint64 { return need[id] }
	return b
}

func TestRequestStart_MemoryAdmission(t *testing.T) {
	const gib = 1 << 30
	docker := newStaticFakeDocker(t, []string{"a", "b"}, nil)
	reg := newRegistry(t, docker, "a", "b")

	m := newTestManager(t, reg, docker)
	m.Memory = newBudget(6*gib, map[string]uint64{"a": 8 * gib, "b": 2 * gib})
	var mem *memadmit.Error
	if err := m.RequestStart(context.Background(), "a"); !errors.As(err, &mem) || mem.Need != 8*gib {
		t.Fatalf("RequestStart(a) = %v, want a memory refusal needing 8 GiB", err)
	}
	if m.Starting("a") {
		t.Fatal("a refused start must not be left in flight")
	}
	if err := m.RequestStart(context.Background(), "b"); err != nil {
		t.Fatalf("RequestStart(b) = %v, want it admitted", err)
	}
	m.Wait()
}

func TestRequestStart_MemoryUnknownIsAdmitted(t *testing.T) {
	docker := newStaticFakeDocker(t, []string{"a"}, nil)
	m := newTestManager(t, newRegistry(t, docker, "a"), docker)
	m.Memory = newBudget(0, map[string]uint64{"a": 99 << 30}) // host memory unreadable
	if err := m.RequestStart(context.Background(), "a"); err != nil {
		t.Fatalf("unreadable host memory must not block a start: %v", err)
	}
	m.Wait()
}

func TestConfirmSwitch_MemoryCountsWhatTheSourceFrees(t *testing.T) {
	const gib = 1 << 30
	docker := newStatefulFakeDocker(t, []string{"palworld"}, []string{"valheim"})
	reg := newRegistry(t, docker, "valheim", "palworld")
	mgr := newTestManager(t, reg, docker)
	mgr.StopPollInterval, mgr.StopPollTimeout = time.Millisecond, time.Second

	// 3 GiB free + 4 GiB freed by valheim covers palworld's 6. Host memory
	// really does rise once valheim is down, which the fake mimics.
	b := newBudget(3*gib, map[string]uint64{"valheim": 4 * gib, "palworld": 6 * gib})
	b.Available = func() uint64 {
		if active, _ := mgr.ActiveGames(context.Background()); len(active) == 0 {
			return 7 * gib
		}
		return 3 * gib
	}
	mgr.Memory = b
	// Without the freed memory the switch would be refused up front; with it, it must go through.
	if err := mgr.ConfirmSwitch(context.Background(), "valheim", "palworld"); err != nil {
		t.Fatalf("ConfirmSwitch() = %v", err)
	}

	// A target bigger than free plus freed is refused before anything stops.
	docker2 := newStatefulFakeDocker(t, []string{"palworld"}, []string{"valheim"})
	m2 := newTestManager(t, newRegistry(t, docker2, "valheim", "palworld"), docker2)
	m2.Memory = newBudget(1*gib, map[string]uint64{"valheim": 2 * gib, "palworld": 6 * gib})
	var mem *memadmit.Error
	if err := m2.ConfirmSwitch(context.Background(), "valheim", "palworld"); !errors.As(err, &mem) {
		t.Fatalf("ConfirmSwitch() = %v, want a memory refusal", err)
	}
	if id, ok, _ := m2.ActiveGame(context.Background()); !ok || id != "valheim" {
		t.Fatalf("the source must keep running after a refused switch, active = %q", id)
	}
}

func TestRequestStart_CooldownFuncOverridesModule(t *testing.T) {
	docker := newStaticFakeDocker(t, []string{"a"}, nil)
	reg := newRegistry(t, docker, "a")
	def, _ := reg.Get("a")
	def.RestartCooldown = time.Hour
	reg, err := games.NewRegistry([]games.GameDef{def})
	if err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, reg, docker)
	m.CooldownFunc = func(string) (time.Duration, bool) { return 0, true } // override: no wait
	if err := m.Stop(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	if err := m.RequestStart(context.Background(), "a"); err != nil {
		t.Fatalf("start with cooldown overridden to 0 = %v, want nil", err)
	}
}

// sleepCtx waits d, or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}
