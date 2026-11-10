package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

func fakeDocker(t *testing.T, script string) *dockerctl.Client {
	t.Helper()
	p := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return &dockerctl.Client{DockerBin: p}
}

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
	m := &Manager{Docker: fakeDocker(t, `case "$1" in ps) echo pal ;; exec) exit 0 ;; esac`), History: r}
	if err := m.RunBackup(context.Background(), def(), "alex"); err != nil {
		t.Fatalf("RunBackup = %v", err)
	}
	if len(r.events) != 1 || !strings.HasPrefix(r.events[0], "backup:pal:alex:done") {
		t.Fatalf("events = %v", r.events)
	}
}

func TestRunBackup_FailureAndPreconditions(t *testing.T) {
	r := &rec{}
	failing := &Manager{Docker: fakeDocker(t, `case "$1" in ps) echo pal ;; exec) echo disk full >&2; exit 1 ;; esac`), History: r}
	if err := failing.RunBackup(context.Background(), def(), "alex"); err == nil {
		t.Fatal("want an error when the command fails")
	}
	if len(r.events) != 1 || !strings.Contains(r.events[0], "failed: ") || !strings.Contains(r.events[0], "disk full") {
		t.Fatalf("events = %v", r.events)
	}

	down := &Manager{Docker: fakeDocker(t, `exit 0`)}
	if err := down.RunBackup(context.Background(), def(), ""); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("not running: %v", err)
	}
	if err := down.RunBackup(context.Background(), games.GameDef{ID: "x"}, ""); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("not configured: %v", err)
	}
}

func TestRequest_SingleFlight(t *testing.T) {
	m := &Manager{Docker: fakeDocker(t, `case "$1" in ps) echo pal ;; exec) sleep 1 ;; esac`)}
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
	m := &Manager{Docker: fakeDocker(t, `case "$1" in exec) echo "1731003600.0 10 a.tgz" ;; esac`)}
	files, err := m.List(context.Background(), def())
	if err != nil || len(files) != 1 || files[0].Name != "a.tgz" {
		t.Fatalf("List = %+v, %v", files, err)
	}
}
