package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
)

func newRoot(t *testing.T) (*Root, string) {
	t.Helper()
	mount := t.TempDir()
	return &Root{Mount: mount, Mode: 0o775, StateFile: filepath.Join(t.TempDir(), "backups-root"), ConfirmNew: true}, mount
}

func TestRoot_FirstUseNeedsConfirmation(t *testing.T) {
	r, mount := newRoot(t)
	r.ConfirmNew = false
	// An unmounted drive on first use looks like a new empty folder: refuse it.
	if err := r.Verify(); !errors.Is(err, ErrRootUnavailable) || !strings.Contains(err.Error(), "backups_confirm_new") {
		t.Fatalf("unconfirmed first use = %v", err)
	}
	if err := r.EnsureGameDir("pal"); err == nil {
		t.Fatal("a game folder was created in an unconfirmed folder")
	}
	if _, err := os.Stat(filepath.Join(mount, "pal")); err == nil {
		t.Fatal("game folder exists")
	}
	if _, err := os.Stat(filepath.Join(mount, markerName)); err == nil || readToken(r.StateFile) != "" {
		t.Fatal("marker or state written without confirmation")
	}
	r.ConfirmNew = true
	if err := r.Verify(); err != nil {
		t.Fatalf("confirmed: %v", err)
	}
	r.ConfirmNew = false // once marked, the flag is no longer needed
	if err := r.Verify(); err != nil {
		t.Fatalf("after first use: %v", err)
	}
}

func TestRoot_FirstUseThenDriveGoesMissing(t *testing.T) {
	r, mount := newRoot(t)
	r.ConfirmNew = true
	if err := r.Verify(); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := r.Verify(); err != nil {
		t.Fatalf("second check: %v", err)
	}
	// The drive disappears: Docker leaves an empty folder with no marker.
	if err := os.Remove(filepath.Join(mount, markerName)); err != nil {
		t.Fatal(err)
	}
	err := r.Verify()
	if !errors.Is(err, ErrRootUnavailable) || !strings.Contains(err.Error(), r.StateFile) {
		t.Fatalf("empty folder after first use = %v, want ErrRootUnavailable naming the state file", err)
	}
	if _, err := os.Stat(filepath.Join(mount, markerName)); err == nil {
		t.Fatal("a marker was recreated on an unrecognised folder")
	}
	// Deleting the remembered token is the deliberate way to accept a new folder.
	_ = os.Remove(r.StateFile)
	if err := r.Verify(); err != nil {
		t.Fatalf("after reset: %v", err)
	}
}

func TestRoot_AdoptsExistingDriveAndRejectsAnotherOne(t *testing.T) {
	r, mount := newRoot(t)
	if err := os.WriteFile(filepath.Join(mount, markerName), []byte("abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(); err != nil { // fresh panel, drive already in use
		t.Fatalf("adopt: %v", err)
	}
	if got := readToken(r.StateFile); got != "abc" {
		t.Fatalf("remembered %q", got)
	}
	if err := os.WriteFile(filepath.Join(mount, markerName), []byte("other\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(); !errors.Is(err, ErrRootUnavailable) {
		t.Fatalf("a different drive = %v", err)
	}
	if err := (&Root{Mount: filepath.Join(mount, "nope")}).Verify(); !errors.Is(err, ErrRootUnavailable) {
		t.Fatalf("missing mount = %v", err)
	}
}

func TestRoot_EnsureGameDirSetsMode(t *testing.T) {
	r, mount := newRoot(t)
	r.Mode = 0o777
	if err := r.EnsureGameDir("palworld-2"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(mount, "palworld-2"))
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o777 {
		t.Fatalf("game dir = %v, %v (the umask must not trim the mode)", fi, err)
	}
}

func TestLocalFiles_IgnoresLinksAndDirs(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i, n := range []string{"old.tgz", "new.tgz"} {
		p := filepath.Join(dir, n)
		_ = os.WriteFile(p, []byte("data"), 0o600)
		ts := now.Add(time.Duration(i) * time.Hour)
		_ = os.Chtimes(p, ts, ts)
	}
	_ = os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	files, err := localFiles(dir)
	if err != nil || len(files) != 2 || files[0].Name != "new.tgz" || files[1].Name != "old.tgz" {
		t.Fatalf("files = %+v, %v", files, err)
	}
	// Pruning to zero removes the real files and never touches the link target.
	if n, err := pruneLocal(dir, 0); err != nil || n != 2 {
		t.Fatalf("prune = %d, %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "secret")); err != nil {
		t.Fatal("prune reached outside the backup folder")
	}
	if _, err := os.Lstat(filepath.Join(dir, "link")); err != nil {
		t.Fatal("prune removed a link it should have ignored")
	}
}

func TestManager_LocalDirListsAndPrunesWithoutExec(t *testing.T) {
	r, mount := newRoot(t)
	if err := r.EnsureGameDir("pal"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(mount, "pal")
	now := time.Now()
	for i := 0; i < 4; i++ {
		p := filepath.Join(dir, "b"+string(rune('a'+i))+".tgz")
		_ = os.WriteFile(p, []byte("x"), 0o600)
		ts := now.Add(time.Duration(i-10) * time.Hour)
		_ = os.Chtimes(p, ts, ts)
	}
	calls := filepath.Join(t.TempDir(), "calls")
	d := games.GameDef{ID: "pal", DisplayName: "Pal", ContainerName: "pal",
		Backup: &games.BackupSpec{Exec: []string{"backup"}, LocalDir: dir, Keep: 2}}
	rec := &rec{}
	m := &Manager{Root: r, History: rec, Docker: fakeDocker(t, `case "$1" in ps) echo pal ;; exec) echo "$*" >> `+calls+`; echo data > `+dir+`/new.tgz ;; esac`)}

	files, err := m.List(context.Background(), d)
	if err != nil || len(files) != 4 || files[0].Name != "bd.tgz" {
		t.Fatalf("List = %+v, %v", files, err)
	}
	if err := m.RunBackup(context.Background(), d, "alex"); err != nil {
		t.Fatal(err)
	}
	if files, _ := m.List(context.Background(), d); len(files) != 2 {
		t.Fatalf("after prune %d files, want 2", len(files))
	}
	if b, _ := os.ReadFile(calls); strings.Count(string(b), "\n") != 1 {
		t.Fatalf("docker exec ran %q, want only the backup command (no find, no prune)", b)
	}

	// The drive vanishes: nothing is listed, backed up or pruned.
	_ = os.Remove(filepath.Join(mount, markerName))
	if _, err := m.List(context.Background(), d); !errors.Is(err, ErrRootUnavailable) {
		t.Fatalf("List on a lost drive = %v", err)
	}
	if err := m.RunBackup(context.Background(), d, "alex"); !errors.Is(err, ErrRootUnavailable) {
		t.Fatalf("RunBackup on a lost drive = %v", err)
	}
	if err := (&Manager{}).RunBackup(context.Background(), d, ""); !errors.Is(err, ErrRootUnavailable) {
		t.Fatalf("no root configured = %v", err)
	}
}

type note struct{ msgs []string }

func (n *note) Notify(_ context.Context, msg string) { n.msgs = append(n.msgs, msg) }

func localGame(dir string) games.GameDef {
	return games.GameDef{ID: "pal", DisplayName: "Pal", ContainerName: "pal",
		Backup: &games.BackupSpec{Exec: []string{"backup"}, LocalDir: dir}}
}

func TestRunBackup_NoNewFileOrEmptyFileIsAFailure(t *testing.T) {
	r, mount := newRoot(t)
	_ = r.EnsureGameDir("pal")
	dir := filepath.Join(mount, "pal")
	for name, script := range map[string]string{
		"writes nothing": `exit 0`,
		"empty file":     `: > ` + dir + `/e.tgz`,
	} {
		rc := &rec{}
		m := &Manager{Root: r, History: rc, Docker: fakeDocker(t, `case "$1" in ps) echo pal ;; exec) `+script+` ;; esac`)}
		if err := m.RunBackup(context.Background(), localGame(dir), "alex"); err == nil {
			t.Fatalf("%s: want a failure", name)
		}
		if len(rc.events) != 1 || !strings.Contains(rc.events[0], "failed:") {
			t.Fatalf("%s: events = %v", name, rc.events)
		}
	}
}

func TestRunBackup_PermissionDeniedGetsAHint(t *testing.T) {
	r, mount := newRoot(t)
	_ = r.EnsureGameDir("pal")
	dir := filepath.Join(mount, "pal")
	rc := &rec{}
	m := &Manager{Root: r, History: rc, Docker: fakeDocker(t, `case "$1" in ps) echo pal ;; exec) echo "tar: Permission denied" >&2; exit 2 ;; esac`)}
	_ = m.RunBackup(context.Background(), localGame(dir), "alex")
	if len(rc.events) != 1 || !strings.Contains(rc.events[0], "backups_dir_mode") {
		t.Fatalf("events = %v", rc.events)
	}
}

func TestRunBackup_RefusalIsRecordedAndNotified(t *testing.T) {
	r, mount := newRoot(t)
	_ = r.EnsureGameDir("pal")
	_ = os.Remove(filepath.Join(mount, markerName)) // the drive is gone
	rc, n := &rec{}, &note{}
	m := &Manager{Root: r, History: rc, Notifier: n, Docker: fakeDocker(t, `exit 0`)}
	// A scheduled or before-stop backup has no actor: it must not fail silently.
	if err := m.RunBackup(context.Background(), localGame(filepath.Join(mount, "pal")), ""); !errors.Is(err, ErrRootUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if len(rc.events) != 1 || !strings.Contains(rc.events[0], "refused") || len(n.msgs) != 1 {
		t.Fatalf("events = %v, notifications = %v", rc.events, n.msgs)
	}
}

func TestRunBackup_RefusedWhenAlmostFull(t *testing.T) {
	r, mount := newRoot(t)
	_ = r.EnsureGameDir("pal")
	m := &Manager{Root: r, MinFree: 1 << 60, Docker: fakeDocker(t, `exit 0`)}
	if err := m.RunBackup(context.Background(), localGame(filepath.Join(mount, "pal")), "alex"); !errors.Is(err, ErrLowSpace) {
		t.Fatalf("err = %v, want ErrLowSpace", err)
	}
}

func TestCheckHealthAndMonitor(t *testing.T) {
	r, mount := newRoot(t)
	_ = r.EnsureGameDir("pal")
	_ = os.MkdirAll(filepath.Join(mount, "old-game"), 0o755)
	n, rc := &note{}, &rec{}
	m := &Manager{Root: r, Notifier: n, History: rc}
	defs := []games.GameDef{localGame(filepath.Join(mount, "pal"))}

	h := m.CheckHealth(defs)
	if !h.OK || len(h.Orphans) != 1 || h.Orphans[0] != "old-game" {
		t.Fatalf("healthy check = %+v", h)
	}
	if !m.Healthy() { // nothing checked yet: no guess
		t.Fatal("unchecked should read healthy")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.RunMonitor(ctx, 20*time.Millisecond, func() []games.GameDef { return defs }); close(done) }()
	time.Sleep(60 * time.Millisecond)
	_ = os.Remove(filepath.Join(mount, markerName)) // the drive goes away
	time.Sleep(100 * time.Millisecond)
	if m.Healthy() || len(n.msgs) != 1 {
		t.Fatalf("after loss: healthy=%v notifications=%v", m.Healthy(), n.msgs)
	}
	// Repeated failing checks do not repeat the alert.
	time.Sleep(100 * time.Millisecond)
	if len(n.msgs) != 1 {
		t.Fatalf("alert repeated: %v", n.msgs)
	}
	_ = os.WriteFile(filepath.Join(mount, markerName), []byte(readToken(r.StateFile)+"\n"), 0o644)
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	if !m.Healthy() || len(n.msgs) != 2 {
		t.Fatalf("after recovery: healthy=%v notifications=%v", m.Healthy(), n.msgs)
	}
}

func TestRemoveGameDir(t *testing.T) {
	mount := t.TempDir()
	root := &Root{Mount: mount, Mode: 0o775, StateFile: filepath.Join(t.TempDir(), "state"), ConfirmNew: true}
	if err := root.EnsureGameDir("mc"); err != nil {
		t.Fatal(err)
	}
	if err := root.EnsureGameDir("keep"); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	_ = os.WriteFile(filepath.Join(outside, "precious"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(mount, "mc", "a.tgz"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(mount, "keep", "b.tgz"), []byte("x"), 0o600)
	// A game can leave a link to anywhere in its own folder; it must go as a link.
	_ = os.Symlink(outside, filepath.Join(mount, "mc", "link"))
	if err := root.RemoveGameDir("mc"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(mount, "mc")); !os.IsNotExist(err) {
		t.Error("folder still there")
	}
	if _, err := os.Stat(filepath.Join(outside, "precious")); err != nil {
		t.Error("followed a link out of the folder")
	}
	if _, err := os.Stat(filepath.Join(mount, "keep", "b.tgz")); err != nil {
		t.Error("another game's backups were touched")
	}
	if err := root.RemoveGameDir("mc"); err != nil {
		t.Errorf("a missing folder is not an error: %v", err)
	}
	for _, bad := range []string{"", "..", "a/b", "."} {
		if err := root.RemoveGameDir(bad); err == nil {
			t.Errorf("RemoveGameDir(%q) succeeded", bad)
		}
	}
	// An unmounted drive (no marker any more) deletes nothing.
	_ = os.Remove(filepath.Join(mount, ".crowsnest-backups"))
	if err := root.RemoveGameDir("keep"); !errors.Is(err, ErrRootUnavailable) {
		t.Errorf("unverified root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mount, "keep", "b.tgz")); err != nil {
		t.Error("deleted on an unverified root")
	}
}
