// Package backup runs a game's configured backup command inside its container
// (`docker exec`) and lists the resulting files. It never touches the
// filesystem itself: whatever the image provides is what gets run.
package backup

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/history"
)

const (
	// runTimeout bounds one backup; a big world on slow disk can take minutes.
	runTimeout  = 10 * time.Minute
	listTimeout = 15 * time.Second
	maxListed   = 30
)

// Errors a caller can map to a response.
var (
	ErrNotConfigured = errors.New("backup: not configured for this game")
	ErrNotRunning    = errors.New("backup: the game isn't running (backups run inside its container)")
	ErrBusy          = errors.New("backup: a backup of this game is already running")
)

// Notifier delivers a message; satisfied by *notify.Discord.
type Notifier interface {
	Notify(ctx context.Context, message string)
}

// File is one backup file found in the game's backup directory.
type File struct {
	Name string    `json:"name"`
	Size int64     `json:"size"`
	Time time.Time `json:"time"`
}

// Manager runs backups. The zero value works; set Docker.
type Manager struct {
	Docker   *dockerctl.Client
	History  history.Recorder
	Notifier Notifier

	// BaseContext is the parent of background backups (cancelled on shutdown).
	BaseContext context.Context

	mu      sync.Mutex
	running map[string]bool
	wg      sync.WaitGroup
}

// Wait blocks until background backups finish (tests, shutdown).
func (m *Manager) Wait() { m.wg.Wait() }

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

// Running reports whether a backup of id is in progress.
func (m *Manager) Running(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running[id]
}

// RunBackup backs d up and waits for it, regardless of who asked. actor is the
// user (empty for an automatic backup before a stop). Used directly by the
// stop path and, via Request, by the dashboard.
func (m *Manager) RunBackup(ctx context.Context, d games.GameDef, actor string) error {
	if d.Backup == nil || len(d.Backup.Exec) == 0 {
		return ErrNotConfigured
	}
	if !m.claim(d.ID) {
		return ErrBusy
	}
	defer m.release(d.ID)
	return m.run(ctx, d, actor)
}

func (m *Manager) run(ctx context.Context, d games.GameDef, actor string) error {
	up, err := m.Docker.Running(ctx, d.ContainerName)
	if err != nil {
		return err
	}
	if !up {
		return ErrNotRunning
	}
	began := time.Now()
	_, err = m.Docker.ExecTimeout(ctx, d.ContainerName, runTimeout, d.Backup.Exec...)
	if err != nil {
		log.Printf("backup: %s failed: %v", d.ID, err)
		m.record(d.ID, actor, "failed: "+tail(err.Error()))
		return fmt.Errorf("backup of %s failed", d.ID)
	}
	took := time.Since(began).Round(time.Second)
	log.Printf("backup: %s done in %s", d.ID, took)
	m.record(d.ID, actor, "done in "+took.String())
	return nil
}

// Request starts a backup in the background and returns at once: ErrBusy,
// ErrNotRunning and ErrNotConfigured come back synchronously; a failure later
// is recorded and notified.
func (m *Manager) Request(ctx context.Context, d games.GameDef, actor string) error {
	if d.Backup == nil || len(d.Backup.Exec) == 0 {
		return ErrNotConfigured
	}
	up, err := m.Docker.Running(ctx, d.ContainerName)
	if err != nil {
		return err
	}
	if !up {
		return ErrNotRunning
	}
	if !m.claim(d.ID) {
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
		if err := m.run(base, d, actor); err != nil {
			m.notify(fmt.Sprintf("Backup of **%s** failed (requested by %s).", d.DisplayName, actor))
			return
		}
		m.notify(fmt.Sprintf("**%s** was backed up (requested by %s).", d.DisplayName, actor))
	}()
	return nil
}

func (m *Manager) record(game, actor, detail string) {
	if m.History != nil {
		m.History.Record(history.KindBackup, game, actor, detail)
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

// List returns d's backup files newest first (at most maxListed). It needs
// list_dir configured and the container running.
func (m *Manager) List(ctx context.Context, d games.GameDef) ([]File, error) {
	if d.Backup == nil || d.Backup.ListDir == "" {
		return nil, ErrNotConfigured
	}
	out, err := m.Docker.ExecTimeout(ctx, d.ContainerName, listTimeout, ListArgs(d.Backup.ListDir)...)
	if err != nil {
		return nil, err
	}
	return parseList(out), nil
}

// ListArgs is the exact command List runs in the container. It is exported so
// the exec guard can allowlist precisely this command and nothing broader.
func ListArgs(dir string) []string {
	return []string{"find", dir, "-maxdepth", "1", "-type", "f", "-printf", "%T@ %s %f\\n"}
}

// parseList reads `find -printf "%T@ %s %f"` output: epoch seconds (maybe
// fractional), size, then the file name (which may contain spaces).
func parseList(out string) []File {
	var files []File
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
		if len(parts) != 3 {
			continue
		}
		secs, err1 := strconv.ParseFloat(parts[0], 64)
		size, err2 := strconv.ParseInt(parts[1], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		files = append(files, File{Name: parts[2], Size: size, Time: time.Unix(int64(secs), 0).UTC()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Time.After(files[j].Time) })
	if len(files) > maxListed {
		files = files[:maxListed]
	}
	return files
}

func tail(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 200 {
		return "…" + string(r[len(r)-200:])
	}
	return s
}
