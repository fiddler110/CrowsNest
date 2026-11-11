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
	return &Root{Mount: mount, Mode: 0o775, StateFile: filepath.Join(t.TempDir(), "backups-root")}, mount
}

func TestRoot_FirstUseThenDriveGoesMissing(t *testing.T) {
	r, mount := newRoot(t)
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
	m := &Manager{Root: r, History: rec, Docker: fakeDocker(t, `case "$1" in ps) echo pal ;; exec) echo "$*" >> `+calls+` ;; esac`)}

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
