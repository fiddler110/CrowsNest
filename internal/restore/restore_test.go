package restore

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/backup"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/dockerctl/dockertest"
	"github.com/fiddler110/crowsnest/internal/games"
)

var apiPrefix = regexp.MustCompile(`^/v[0-9.]+`)

// engine is a tiny Docker Engine: a game container and any helper created.
type engine struct {
	mu         sync.Mutex
	gameUp     bool
	helper     bool // the helper container exists
	helperExit int
	log        []string
	exec       *dockertest.Fake // answers exec (the safety backup's command)
}

func (e *engine) note(s string) {
	e.mu.Lock()
	e.log = append(e.log, s)
	e.mu.Unlock()
}

func (e *engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := apiPrefix.ReplaceAllString(r.URL.Path, "")
	if strings.HasPrefix(p, "/exec/") || strings.HasSuffix(p, "/exec") {
		e.exec.Handler().ServeHTTP(w, r)
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case p == "/_ping":
		w.WriteHeader(200)
	case p == "/containers/create":
		e.log = append(e.log, "create "+r.URL.Query().Get("name"))
		e.helper = true
		w.WriteHeader(201)
		fmt.Fprint(w, `{"Id":"abc"}`)
	case p == "/containers/pal/json":
		fmt.Fprintf(w, `{"State":{"Running":%v,"FinishedAt":"0001-01-01T00:00:00Z"}}`, e.gameUp)
	case p == "/containers/pal-restore/json" && r.Method == http.MethodGet:
		if !e.helper {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"message":"no such container"}`)
			return
		}
		fmt.Fprintf(w, `{"State":{"Running":false,"ExitCode":%d,"FinishedAt":"2026-01-01T00:00:00Z"}}`, e.helperExit)
	case p == "/containers/pal-restore/json":
		w.WriteHeader(404)
	case p == "/containers/pal-restore" && r.Method == http.MethodDelete:
		e.log = append(e.log, "remove pal-restore")
		e.helper = false
		w.WriteHeader(204)
	case strings.HasSuffix(p, "/start") && r.Method == http.MethodPost:
		w.WriteHeader(204)
	case strings.HasSuffix(p, "/logs"):
		s := "tar: no such file"
		b := make([]byte, 8, 8+len(s))
		b[0] = 2
		binary.BigEndian.PutUint32(b[4:], uint32(len(s)))
		_, _ = w.Write(append(b, s...))
	default:
		w.WriteHeader(404)
	}
}

type ctl struct {
	e        *engine
	stopErr  error
	startErr error
	onStop   func()
}

func (c *ctl) Stop(_ context.Context, id string) error {
	c.e.note("stop " + id)
	if c.onStop != nil {
		c.onStop()
	}
	if c.stopErr != nil {
		return c.stopErr
	}
	c.e.mu.Lock()
	c.e.gameUp = false
	c.e.mu.Unlock()
	return nil
}

func (c *ctl) RequestStart(_ context.Context, id string) error {
	c.e.note("start " + id)
	return c.startErr
}

type rec struct {
	mu     sync.Mutex
	events []string
}

func (r *rec) Record(kind, game, actor, detail string) {
	r.mu.Lock()
	r.events = append(r.events, kind+":"+game+":"+actor+":"+detail)
	r.mu.Unlock()
}

type note struct{ msgs []string }

func (n *note) Notify(_ context.Context, m string) { n.msgs = append(n.msgs, m) }

type fixture struct {
	e   *engine
	c   *ctl
	m   *Manager
	rec *rec
	n   *note
	def games.GameDef
	dir string
}

func newFixture(t *testing.T, keep int) *fixture {
	t.Helper()
	e := &engine{gameUp: true, exec: dockertest.New(t)}
	e.exec.Add("pal", true)
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)
	docker := &dockerctl.Client{Host: "tcp://" + strings.TrimPrefix(srv.URL, "http://"), HTTP: srv.Client()}

	mount := t.TempDir()
	root := &backup.Root{Mount: mount, Mode: 0o775, StateFile: filepath.Join(t.TempDir(), "state"), ConfirmNew: true}
	if err := root.EnsureGameDir("pal"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(mount, "pal")
	now := time.Now()
	for i, name := range []string{"old.tgz", "mid.tgz", "new.tgz"} { // old is the oldest
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte("x"), 0o600)
		ts := now.Add(time.Duration(i-10) * time.Hour)
		_ = os.Chtimes(p, ts, ts)
	}
	r, n := &rec{}, &note{}
	c := &ctl{e: e}
	def := games.GameDef{ID: "pal", DisplayName: "Pal", ContainerName: "pal",
		Backup: &games.BackupSpec{Exec: []string{"backup"}, LocalDir: dir, BeforeStop: true, Keep: keep, CanRestore: true}}
	m := &Manager{
		Docker: docker, Control: c, Backups: &backup.Manager{Docker: docker, Root: root}, History: r, Notifier: n,
		PollInterval: time.Millisecond,
		Spec: func(id, file string) (dockerctl.CreateSpec, bool) {
			return dockerctl.CreateSpec{Name: id + "-restore", Image: "img", Network: "games",
				Env: []string{"CROWSNEST_RESTORE_FILE=/b/" + file}, Entrypoint: []string{"/bin/sh", "-c", "true"}, NoRestart: true}, true
		},
	}
	return &fixture{e: e, c: c, m: m, rec: r, n: n, def: def, dir: dir}
}

func TestRestore_RunningGameIsStoppedRestoredAndStartedAgain(t *testing.T) {
	f := newFixture(t, 0)
	if err := f.m.Request(context.Background(), f.def, "mid.tgz", "alex", true); err != nil {
		t.Fatalf("Request = %v", err)
	}
	f.m.Wait()
	want := "stop pal,create pal-restore,remove pal-restore,start pal"
	if got := strings.Join(f.e.log, ","); got != want {
		t.Fatalf("sequence = %s, want %s", got, want)
	}
	if len(f.rec.events) != 1 || !strings.HasPrefix(f.rec.events[0], "restore:pal:alex:restored mid.tgz") || len(f.n.msgs) != 1 {
		t.Fatalf("events = %v, notifications = %v", f.rec.events, f.n.msgs)
	}
	if f.m.Running("pal") {
		t.Fatal("still marked running")
	}
}

func TestRestore_StoppedGameStaysStopped(t *testing.T) {
	f := newFixture(t, 0)
	f.e.gameUp = false
	if err := f.m.Request(context.Background(), f.def, "mid.tgz", "alex", true); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if got := strings.Join(f.e.log, ","); got != "create pal-restore,remove pal-restore" {
		t.Fatalf("sequence = %s", got)
	}
	if !strings.Contains(f.rec.events[0], "start it when ready") {
		t.Fatalf("events = %v", f.rec.events)
	}
}

func TestRestore_FailureLeavesTheGameStoppedAndSaysWhy(t *testing.T) {
	f := newFixture(t, 0)
	f.e.helperExit = 2
	if err := f.m.Request(context.Background(), f.def, "mid.tgz", "alex", true); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	for _, s := range f.e.log {
		if s == "start pal" {
			t.Fatal("the game was started after a failed restore")
		}
	}
	if !strings.Contains(f.e.log[len(f.e.log)-1], "remove pal-restore") {
		t.Fatalf("helper not removed: %v", f.e.log)
	}
	ev := f.rec.events[0]
	if !strings.Contains(ev, "failed") || !strings.Contains(ev, "exit status 2") || !strings.Contains(ev, "no such file") || !strings.Contains(ev, "left stopped") {
		t.Fatalf("event = %q", ev)
	}
	if len(f.n.msgs) != 1 {
		t.Fatalf("notifications = %v", f.n.msgs)
	}
}

func TestRestore_StopFailureChangesNothing(t *testing.T) {
	f := newFixture(t, 0)
	f.c.stopErr = errors.New("boom")
	_ = f.m.Request(context.Background(), f.def, "mid.tgz", "alex", true)
	f.m.Wait()
	if got := strings.Join(f.e.log, ","); got != "stop pal" {
		t.Fatalf("sequence = %s, want only the stop", got)
	}
	if !strings.Contains(f.rec.events[0], "before the game was stopped") {
		t.Fatalf("events = %v", f.rec.events)
	}
}

func TestRestore_RefusesBeforeStoppingAnything(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 0)
	for _, name := range []string{"", "../etc/passwd", "a b.tgz", "sub/x.tgz", ".hidden"} {
		if err := f.m.Request(ctx, f.def, name, "alex", true); !errors.Is(err, ErrBadFile) {
			t.Errorf("%q = %v, want ErrBadFile", name, err)
		}
	}
	if err := f.m.Request(ctx, f.def, "missing.tgz", "alex", true); !errors.Is(err, ErrBadFile) {
		t.Errorf("missing file = %v", err)
	}
	noRestore := f.def
	noRestore.Backup = &games.BackupSpec{Exec: []string{"b"}, LocalDir: f.dir}
	if err := f.m.Request(ctx, noRestore, "mid.tgz", "alex", true); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no restore command = %v", err)
	}
	if len(f.e.log) != 0 {
		t.Fatalf("refusals touched docker: %v", f.e.log)
	}

	// keep 3 with three files: stopping adds a fourth and prunes old.tgz, which is
	// the one being asked for.
	f = newFixture(t, 3)
	if err := f.m.Request(ctx, f.def, "old.tgz", "alex", true); !errors.Is(err, ErrWouldPrune) {
		t.Fatalf("oldest under keep = %v, want ErrWouldPrune", err)
	}
	if err := f.m.Request(ctx, f.def, "mid.tgz", "alex", true); err != nil {
		t.Fatalf("a file that survives the prune: %v", err)
	}
	f.m.Wait()
	// With the game stopped there is no safety backup to prune anything.
	f = newFixture(t, 3)
	f.e.gameUp = false
	if err := f.m.Request(ctx, f.def, "old.tgz", "alex", true); err != nil {
		t.Fatalf("stopped game: %v", err)
	}
	f.m.Wait()
}

func TestRestore_OneAtATime(t *testing.T) {
	f := newFixture(t, 0)
	release, ok := f.m.Backups.Hold("pal") // a backup is running
	if !ok {
		t.Fatal("hold")
	}
	if err := f.m.Request(context.Background(), f.def, "mid.tgz", "alex", true); !errors.Is(err, ErrBusy) {
		t.Fatalf("during a backup = %v, want ErrBusy", err)
	}
	release()
	if err := f.m.Request(context.Background(), f.def, "mid.tgz", "alex", true); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
}

// Stopping a game takes its before-stop backup, which a restore's own hold on
// the game would refuse; the hold must come after the stop.
func TestRestore_SafetyBackupIsNotBlockedByTheRestoreItself(t *testing.T) {
	f := newFixture(t, 0)
	blocked := false
	f.c.onStop = func() {
		release, ok := f.m.Backups.Hold("pal")
		if !ok {
			blocked = true
			return
		}
		release()
	}
	if err := f.m.Request(context.Background(), f.def, "mid.tgz", "alex", true); err != nil {
		t.Fatalf("Request = %v", err)
	}
	f.m.Wait()
	if blocked {
		t.Fatal("the game was held against backups while it was being stopped")
	}
}

func TestRestore_StoppedGameNeedsAcknowledgementOfNoBackup(t *testing.T) {
	f := newFixture(t, 0)
	f.e.gameUp = false
	if err := f.m.Request(context.Background(), f.def, "mid.tgz", "alex", false); !errors.Is(err, ErrNoSafetyBackup) {
		t.Fatalf("Request = %v, want ErrNoSafetyBackup", err)
	}
	f.m.Wait()
	if len(f.e.log) != 0 || f.m.Running("pal") {
		t.Fatalf("something ran: %v", f.e.log)
	}
}

func TestRestore_RunningGameIsAlwaysBackedUpFirst(t *testing.T) {
	f := newFixture(t, 0)
	f.def.Backup.BeforeStop = false // the module does not back up before a stop; a restore still must
	if err := f.m.Request(context.Background(), f.def, "mid.tgz", "alex", false); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	// The fake docker writes no new backup file, so the safety backup fails: nothing may be stopped or replaced.
	if len(f.e.log) != 0 {
		t.Fatalf("the game was touched after a failed safety backup: %v", f.e.log)
	}
	if len(f.rec.events) == 0 || !strings.Contains(strings.Join(f.rec.events, "|"), "safety backup") {
		t.Fatalf("events = %v", f.rec.events)
	}
}

func TestRestore_WouldPruneAppliesEvenWithoutBeforeStop(t *testing.T) {
	f := newFixture(t, 3)
	f.def.Backup.BeforeStop = false
	if err := f.m.Request(context.Background(), f.def, "old.tgz", "alex", false); !errors.Is(err, ErrWouldPrune) {
		t.Fatalf("Request = %v, want ErrWouldPrune", err)
	}
}
