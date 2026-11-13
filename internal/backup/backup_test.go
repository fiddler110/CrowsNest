package backup

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/dockerctl/dockertest"
	"github.com/fiddler110/crowsnest/internal/games"
)

// fakeDocker is an engine with the container "pal" up (or not); exec answers every command run in it.
func fakeDocker(t *testing.T, running bool, exec dockertest.ExecFunc) *dockerctl.Client {
	t.Helper()
	f := dockertest.New(t)
	f.Add("pal", running)
	f.Exec = exec
	return f.Client()
}

// ok is a command that succeeds quietly.
func ok(string, []string, string) (string, string, int) { return "", "", 0 }

// failing is a command that exits non-zero with msg on stderr.
func failing(msg string) dockertest.ExecFunc {
	return func(string, []string, string) (string, string, int) { return "", msg + "\n", 1 }
}

// isShell is a `sh -c` command, which is how the prune runs.
func isShell(cmd []string) bool { return len(cmd) > 1 && cmd[0] == "sh" && cmd[1] == "-c" }

type rec struct{ events []string }

func (r *rec) Record(kind, game, actor, detail string) {
	r.events = append(r.events, kind+":"+game+":"+actor+":"+detail)
}

func def() games.GameDef {
	return games.GameDef{ID: "pal", DisplayName: "Pal", ContainerName: "pal",
		Backup: &games.BackupSpec{Exec: []string{"backup"}, ListDir: "/backups"}}
}

func TestParseList(t *testing.T) {
	files := parseList("1731000000.5 100 old backup.tgz\n1731003600.0 2048 new.tgz\ngarbage\n")
	if len(files) != 2 || files[0].Name != "new.tgz" || files[1].Name != "old backup.tgz" || files[0].Size != 2048 {
		t.Fatalf("files = %+v", files)
	}
}

func TestRunBackup(t *testing.T) {
	r := &rec{}
	m := &Manager{Docker: fakeDocker(t, true, ok), History: r}
	if err := m.RunBackup(context.Background(), def(), "alex"); err != nil {
		t.Fatalf("RunBackup = %v", err)
	}
	if len(r.events) != 1 || !strings.HasPrefix(r.events[0], "backup:pal:alex:done") {
		t.Fatalf("events = %v", r.events)
	}
}

func TestRunBackup_FailureAndPreconditions(t *testing.T) {
	r := &rec{}
	failing := &Manager{Docker: fakeDocker(t, true, failing("disk full")), History: r}
	if err := failing.RunBackup(context.Background(), def(), "alex"); err == nil {
		t.Fatal("want an error when the command fails")
	}
	if len(r.events) != 1 || !strings.Contains(r.events[0], "failed: ") || !strings.Contains(r.events[0], "disk full") {
		t.Fatalf("events = %v", r.events)
	}

	down := &Manager{Docker: fakeDocker(t, false, ok)}
	if err := down.RunBackup(context.Background(), def(), ""); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("not running: %v", err)
	}
	if err := down.RunBackup(context.Background(), games.GameDef{ID: "x"}, ""); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("not configured: %v", err)
	}
}

func TestRequest_SingleFlight(t *testing.T) {
	m := &Manager{Docker: fakeDocker(t, true, func(string, []string, string) (string, string, int) { time.Sleep(time.Second); return "", "", 0 })}
	if err := m.Request(context.Background(), def(), "a"); err != nil {
		t.Fatal(err)
	}
	if err := m.Request(context.Background(), def(), "b"); !errors.Is(err, ErrBusy) {
		t.Fatalf("second Request = %v, want ErrBusy", err)
	}
	if !m.Running("pal") {
		t.Fatal("Running = false during a backup")
	}
	m.Wait()
	if m.Running("pal") {
		t.Fatal("still running after Wait")
	}
	_ = time.Second
}

func TestList(t *testing.T) {
	m := &Manager{Docker: fakeDocker(t, true, func(string, []string, string) (string, string, int) { return "1731003600.0 10 a.tgz\n", "", 0 })}
	files, err := m.List(context.Background(), def())
	if err != nil || len(files) != 1 || files[0].Name != "a.tgz" {
		t.Fatalf("List = %+v, %v", files, err)
	}
}

func TestPruneArgs_KeepsNewestFiles(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for i, name := range []string{"oldest.tgz", "with space.tgz", "mid.tgz", "newest.tgz"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		ts := now.Add(time.Duration(i-10) * time.Hour)
		if err := os.Chtimes(p, ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	args := PruneArgs(dir, 2)
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil { // #nosec G204 -- test
		t.Fatalf("prune: %v: %s", err, out)
	}
	var left []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if strings.Join(left, ",") != "mid.tgz,newest.tgz,subdir" {
		t.Fatalf("left = %v, want the two newest files and the untouched subdir", left)
	}
}

func TestRunBackup_PrunesAfterSuccess(t *testing.T) {
	var calls []string
	m := &Manager{Docker: fakeDocker(t, true, func(_ string, cmd []string, _ string) (string, string, int) {
		if isShell(cmd) {
			calls = append(calls, "prune")
		} else {
			calls = append(calls, "backup")
		}
		return "", "", 0
	}), History: &rec{}}
	d := def()
	d.Backup.Keep = 3
	if err := m.RunBackup(context.Background(), d, "alex"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, "\n") != "backup\nprune" {
		t.Fatalf("exec calls = %q, want the backup then the prune", calls)
	}

	// A failing prune doesn't fail the backup, but is recorded.
	r := &rec{}
	m = &Manager{Docker: fakeDocker(t, true, func(_ string, cmd []string, _ string) (string, string, int) {
		if isShell(cmd) {
			return "", "no find\n", 1
		}
		return "", "", 0
	}), History: r}
	if err := m.RunBackup(context.Background(), d, "alex"); err != nil {
		t.Fatalf("backup failed because the prune did: %v", err)
	}
	if len(r.events) != 1 || !strings.Contains(r.events[0], "pruning old backups failed") {
		t.Fatalf("events = %v", r.events)
	}
}
