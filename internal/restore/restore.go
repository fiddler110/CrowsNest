// Package restore puts a backup back. The game is stopped (which takes a fresh
// backup first, when the module asks for one), a one-shot container from the
// game's own image runs the module's restore command against the game's data
// folders and its backups folder (read-only), and the game is started again if
// it was running. The panel never touches game data itself.
package restore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/backup"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/history"
)

// Errors a caller can map to a response.
var (
	ErrNotConfigured  = errors.New("restore: this game has no restore command (or no shared backups folder)")
	ErrBadFile        = errors.New("restore: that is not a backup file of this game")
	ErrBusy           = errors.New("restore: a restore or backup of this game is already running")
	ErrNoSafetyBackup = errors.New("restore: the game is stopped, so no safety backup of its current world can be taken first")
	ErrWouldPrune     = errors.New("restore: the safety backup taken before the restore would delete that file under backup.keep")
)

// Controller starts and stops games; satisfied by *exclusivity.Manager.
type Controller interface {
	Stop(ctx context.Context, id string) error
	RequestStart(ctx context.Context, id string) error
}

// Notifier delivers a message; satisfied by *notify.Discord.
type Notifier interface {
	Notify(ctx context.Context, message string)
}

// Spec builds the one-shot container for restoring file of game id.
type Spec func(id, file string) (dockerctl.CreateSpec, bool)

var fileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)

// Manager runs restores. Set every field except the intervals.
type Manager struct {
	Docker   *dockerctl.Client
	Control  Controller
	Backups  *backup.Manager
	Spec     Spec
	History  history.Recorder
	Notifier Notifier

	// BaseContext is the parent of background restores (cancelled on shutdown).
	BaseContext context.Context
	// Timeout bounds the restore command itself (default 15 minutes);
	// PollInterval is how often it is checked (default 1 second).
	Timeout      time.Duration
	PollInterval time.Duration

	mu      sync.Mutex
	running map[string]bool
	wg      sync.WaitGroup
}

// Wait blocks until background restores finish (tests, shutdown).
func (m *Manager) Wait() { m.wg.Wait() }

// Running reports whether a restore of id is in progress.
func (m *Manager) Running(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running[id]
}

func (m *Manager) claim(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running == nil {
		m.running = map[string]bool{}
	}
	if m.running[id] {
		return false
	}
	m.running[id] = true
	return true
}

func (m *Manager) release(id string) {
	m.mu.Lock()
	delete(m.running, id)
	m.mu.Unlock()
}

// Request checks a restore can go ahead and starts it in the background. Every
// refusal comes back here, before anything is stopped; the outcome of the run
// itself is recorded and notified.
//
// A running game always gets a safety backup of its current world first (even
// when its module does not back up before every stop). A stopped game cannot be
// backed up from outside, so that is refused with ErrNoSafetyBackup unless
// withoutBackup says the caller accepted losing the current world.
func (m *Manager) Request(ctx context.Context, d games.GameDef, file, actor string, withoutBackup bool) error {
	if d.Backup == nil || !d.Backup.CanRestore || d.Backup.LocalDir == "" || m.Spec == nil {
		return ErrNotConfigured
	}
	if !fileRe.MatchString(file) {
		return ErrBadFile
	}
	if _, ok := m.Spec(d.ID, file); !ok {
		return ErrNotConfigured
	}
	idx, err := m.Backups.Locate(d, file)
	switch {
	case errors.Is(err, backup.ErrNoSuchFile):
		return ErrBadFile
	case err != nil:
		return err
	}
	up, err := m.Docker.Running(ctx, d.ContainerName)
	if err != nil {
		return err
	}
	if !up && !withoutBackup {
		return ErrNoSafetyBackup
	}
	// The safety backup is a new file, and keep then prunes the oldest ones:
	// refuse rather than delete the very file being restored.
	if up && d.Backup.Keep > 0 && idx+1 >= d.Backup.Keep {
		return fmt.Errorf("%w (it is number %d of %d kept)", ErrWouldPrune, idx+1, d.Backup.Keep)
	}
	if m.Backups.Running(d.ID) || !m.claim(d.ID) {
		return ErrBusy
	}
	base := m.BaseContext
	if base == nil {
		base = context.Background()
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer m.release(d.ID)
		m.run(base, d, file, actor, up)
	}()
	return nil
}

// hold claims the game against backups, waiting briefly for one that started
// while the game was stopping.
func (m *Manager) hold(ctx context.Context, id string) (func(), bool) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		if release, ok := m.Backups.Hold(id); ok {
			return release, true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, false
		}
		time.Sleep(m.poll())
	}
}

func (m *Manager) timeout() time.Duration {
	if m.Timeout > 0 {
		return m.Timeout
	}
	return 15 * time.Minute
}

func (m *Manager) poll() time.Duration {
	if m.PollInterval > 0 {
		return m.PollInterval
	}
	return time.Second
}

func (m *Manager) run(ctx context.Context, d games.GameDef, file, actor string, wasUp bool) {
	began := time.Now()
	fail := func(stage string, err error) {
		msg := fmt.Sprintf("restore of %s failed %s: %s", file, stage, tail(err.Error()))
		if !strings.HasPrefix(stage, "before the game was stopped") {
			msg += ". The game is left stopped and its data may be partly restored; the backup file itself is untouched"
		}
		log.Printf("restore: %s: %q", d.ID, msg)
		m.record(d.ID, actor, msg)
		m.notify(fmt.Sprintf("⚠️ Restore of **%s** from %s failed (requested by %s): %s", d.DisplayName, file, actor, tail(err.Error())))
	}
	if wasUp {
		// Stop backs up first only when the module asks for it; a restore always does.
		if !d.Backup.BeforeStop && len(d.Backup.Exec) > 0 {
			if err := m.Backups.RunBackup(ctx, d, actor); err != nil {
				fail("before the game was stopped (the safety backup)", err)
				return
			}
		}
		if err := m.Control.Stop(ctx, d.ID); err != nil {
			fail("before the game was stopped", err)
			return
		}
	}
	// Held only now: stopping the game takes its own backup, which a hold would refuse.
	release, ok := m.hold(ctx, d.ID)
	if !ok {
		fail("preparing the restore", ErrBusy)
		return
	}
	defer release()
	spec, ok := m.Spec(d.ID, file)
	if !ok {
		fail("preparing the restore", ErrNotConfigured)
		return
	}
	if err := m.removeHelper(ctx, spec.Name); err != nil { // a leftover of an interrupted restore
		fail("clearing an old restore container", err)
		return
	}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			rctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if err := m.Docker.Remove(rctx, spec.Name); err != nil {
				log.Printf("restore: removing %s: %v", spec.Name, err)
			}
		})
	}
	defer cleanup()
	if err := m.Docker.Create(ctx, spec); err != nil {
		fail("creating the restore container", err)
		return
	}
	if err := m.Docker.Start(ctx, dockerctl.Target{ContainerName: spec.Name}); err != nil {
		fail("starting the restore container", err)
		return
	}
	st, err := m.wait(ctx, spec.Name)
	if err != nil {
		fail("waiting for the restore command", err)
		return
	}
	if st.ExitCode != 0 {
		out := m.logs(ctx, spec.Name) // before the container (and its logs) are removed
		cleanup()
		fail("in the restore command", fmt.Errorf("exit status %d: %s", st.ExitCode, out))
		return
	}
	cleanup() // the game starts again only once the helper is gone
	detail := fmt.Sprintf("restored %s in %s", file, time.Since(began).Round(time.Second))
	if !wasUp {
		m.record(d.ID, actor, detail+" (the game was stopped; start it when ready)")
		m.notify(fmt.Sprintf("**%s** was restored from %s by %s. It was stopped; start it when ready.", d.DisplayName, file, actor))
		return
	}
	if err := m.Control.RequestStart(ctx, d.ID); err != nil {
		m.record(d.ID, actor, detail+"; it was not started again: "+tail(err.Error()))
		m.notify(fmt.Sprintf("**%s** was restored from %s by %s, but could not be started again (%s). Start it yourself.", d.DisplayName, file, actor, tail(err.Error())))
		return
	}
	m.record(d.ID, actor, detail+"; starting again")
	m.notify(fmt.Sprintf("**%s** was restored from %s by %s and is starting again.", d.DisplayName, file, actor))
}

// removeHelper deletes a container of that name if there is one.
func (m *Manager) removeHelper(ctx context.Context, name string) error {
	exists, err := m.Docker.Exists(ctx, name)
	if err != nil || !exists {
		return err
	}
	return m.Docker.Remove(ctx, name)
}

// wait polls until the container has stopped or the timeout passes.
func (m *Manager) wait(ctx context.Context, name string) (dockerctl.ContainerState, error) {
	deadline := time.Now().Add(m.timeout())
	for {
		st, err := m.Docker.State(ctx, name)
		if err != nil {
			return st, err
		}
		if !st.Running && !st.FinishedAt.IsZero() {
			return st, nil
		}
		if time.Now().After(deadline) {
			return st, fmt.Errorf("it did not finish within %s", m.timeout())
		}
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-time.After(m.poll()):
		}
	}
}

// logs returns the last lines the restore command printed.
func (m *Manager) logs(ctx context.Context, name string) string {
	rc, err := m.Docker.Logs(ctx, name, "", "20")
	if err != nil {
		return "(no output: " + err.Error() + ")"
	}
	defer rc.Close()
	b, _ := io.ReadAll(io.LimitReader(rc, 4096))
	return strings.TrimSpace(string(b))
}

func (m *Manager) record(game, actor, detail string) {
	if m.History != nil {
		m.History.Record(history.KindRestore, game, actor, detail)
	}
}

func (m *Manager) notify(msg string) {
	if m.Notifier == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m.Notifier.Notify(ctx, msg)
}

func tail(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 300 {
		return "…" + string(r[len(r)-300:])
	}
	return s
}
