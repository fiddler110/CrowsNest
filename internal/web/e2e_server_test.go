package web

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"testing"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/backup"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/managed"
	"github.com/fiddler110/crowsnest/internal/restore"
)

// TestE2EServer serves the dashboard on E2E_ADDR over a fake docker, for the browser tests in e2e/. It is skipped
// unless E2E_ADDR is set, and runs until interrupted. The one user is admin / correct-horse-battery.
func TestE2EServer(t *testing.T) {
	addr := os.Getenv("E2E_ADDR")
	if addr == "" {
		t.Skip("E2E_ADDR not set; this is the server the browser tests in e2e/ start")
	}
	state := t.TempDir()
	docker := fakeDockerClient(t, nil, "alpha", "bravo", "charlie")
	var defs []games.GameDef
	for _, id := range []string{"alpha", "bravo"} {
		defs = append(defs, games.GameDef{ID: id, DisplayName: id, ContainerName: id,
			Status: &games.DockerStatusChecker{Docker: docker}, Players: games.UnknownPlayerCounter{}})
	}
	// "charlie" has backups on a shared folder and can restore them: the restore dialog's flow.
	mount := filepath.Join(state, "backups")
	if err := os.MkdirAll(mount, 0o750); err != nil {
		t.Fatal(err)
	}
	root := &backup.Root{Mount: mount, Mode: 0o775, StateFile: filepath.Join(state, "backup-state"), ConfirmNew: true}
	if err := root.EnsureGameDir("charlie"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount, "charlie", "world-1.tgz"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	defs = append(defs, games.GameDef{ID: "charlie", DisplayName: "charlie", ContainerName: "charlie",
		Status: &games.DockerStatusChecker{Docker: docker}, Players: games.UnknownPlayerCounter{},
		Backup: &games.BackupSpec{Exec: []string{"backup"}, LocalDir: filepath.Join(mount, "charlie"), Keep: 5, CanRestore: true}})
	h := newHarnessFromDefs(t, docker, defs)
	hash, err := auth.HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	users := auth.Users{"admin": {Role: auth.RoleAdmin, Hash: hash}}
	h.App.Auth.Users = users
	h.App.Auth.Sessions.Users = users

	backups := &backup.Manager{Docker: docker, Root: root}
	h.App.Backups = backups
	h.App.Restore = &restore.Manager{Docker: docker, Backups: backups,
		Spec: func(id, file string) (dockerctl.CreateSpec, bool) {
			return dockerctl.CreateSpec{Name: id + "-restore", Image: "img", NoRestart: true}, true
		}}
	h.App.Managed = &e2eManaged{}

	prof, err := auth.NewProfileStore(filepath.Join(state, "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	h.App.Profiles = prof

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h.mux()}
	go func() { _ = srv.Serve(ln) }()
	fmt.Println("e2e server listening on", ln.Addr())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	_ = srv.Close()
}

// e2eManaged is the "add a game" backend: one module, and a list that grows when a game is enabled.
type e2eManaged struct {
	mu   sync.Mutex
	list []managed.Info
}

func (f *e2eManaged) Catalogue() []managed.ModuleInfo {
	return []managed.ModuleInfo{{ID: "demo", Name: "Demo Game", Description: "A game for the browser tests.", Image: "example/demo", DefaultTag: "latest", Allowed: true, Bundled: true}}
}
func (f *e2eManaged) List() []managed.Info {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]managed.Info{}, f.list...)
}
func (f *e2eManaged) Preview(r managed.Request) (*managed.Plan, error) {
	return &managed.Plan{Service: r.ID, Scope: r.ID, Fits: true, Container: r.ID, Image: "example/demo:latest", Connect: "host:1234"}, nil
}
func (f *e2eManaged) Enable(r managed.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = append(f.list, managed.Info{ID: r.ID, Module: r.Module, State: "ready", DisplayName: r.DisplayName})
	return nil
}
func (f *e2eManaged) Update(managed.Request) error                 { return nil }
func (f *e2eManaged) Refresh(string) error                         { return nil }
func (f *e2eManaged) Rollback(string) error                        { return nil }
func (f *e2eManaged) Disable(string, managed.DisableOptions) error { return nil }
func (f *e2eManaged) Policy() (managed.PolicyState, error)         { return managed.PolicyState{}, nil }
func (f *e2eManaged) SetPolicy(managed.PolicyDoc) error            { return nil }
func (f *e2eManaged) SetAllowed(string, bool) error                { return nil }
