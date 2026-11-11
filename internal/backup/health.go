package backup

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
)

// DefaultMinFree is the free space below which a backup is refused rather than
// started: a backup that fills the drive can take the game's own saves with it.
const DefaultMinFree = 1 << 30

// ErrLowSpace means the backups folder is nearly full.
var ErrLowSpace = errors.New("backup: the backups folder is almost full")

// Health is the latest result of the periodic folder check.
type Health struct {
	Checked  bool      `json:"checked"`
	OK       bool      `json:"ok"`
	Problems []string  `json:"problems,omitempty"`
	Free     uint64    `json:"free"`
	Orphans  []string  `json:"orphans,omitempty"` // folders no game uses
	At       time.Time `json:"at"`
}

type healthState struct {
	mu   sync.Mutex
	last Health
}

// Health returns the most recent check. Before the first one, Checked is false
// and OK is true so nothing is flagged on a guess.
func (m *Manager) Health() Health {
	m.health.mu.Lock()
	defer m.health.mu.Unlock()
	if !m.health.last.Checked {
		return Health{OK: true}
	}
	return m.health.last
}

// Healthy reports whether the backups folder passed its latest check (true when
// there is no shared folder or no check has run).
func (m *Manager) Healthy() bool {
	if m.Root == nil {
		return true
	}
	return m.Health().OK
}

func freeSpace(path string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true // #nosec G115 -- block counts are non-negative
}

func (m *Manager) minFree() uint64 {
	if m.MinFree > 0 {
		return uint64(m.MinFree)
	}
	return DefaultMinFree
}

// writable proves the panel can create files in dir by creating and removing one.
func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".crowsnest-probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

// CheckHealth inspects the shared folder and every game's sub-folder: the
// folder is the one used before, has room, and each game's folder can be
// written; folders no game uses are listed. defs are the games to consider.
func (m *Manager) CheckHealth(defs []games.GameDef) Health {
	h := Health{Checked: true, OK: true, At: time.Now()}
	if m.Root == nil {
		return h
	}
	if err := m.Root.Verify(); err != nil {
		h.OK = false
		h.Problems = append(h.Problems, strings.TrimPrefix(err.Error(), ErrRootUnavailable.Error()+": "))
		return h
	}
	if free, ok := freeSpace(m.Root.Mount); ok {
		h.Free = free
		if free < m.minFree() {
			h.OK = false
			h.Problems = append(h.Problems, fmt.Sprintf("only %d MiB free in the backups folder", free>>20))
		}
	}
	used := map[string]bool{}
	for _, d := range defs {
		if d.Backup == nil || d.Backup.LocalDir == "" {
			continue
		}
		used[filepath.Base(d.Backup.LocalDir)] = true
		if err := writable(d.Backup.LocalDir); err != nil {
			h.OK = false
			h.Problems = append(h.Problems, fmt.Sprintf("%s: the panel cannot write to its backup folder (%v)", d.ID, err))
		}
	}
	if ents, err := os.ReadDir(m.Root.Mount); err == nil {
		for _, e := range ents {
			if e.IsDir() && !used[e.Name()] {
				h.Orphans = append(h.Orphans, e.Name())
			}
		}
		sort.Strings(h.Orphans)
	}
	return h
}

// RunMonitor re-checks the folder every interval until ctx ends and reports
// changes: a drive that disappears or fills is recorded and notified once, and
// so is its return. games supplies the current games (they change at runtime).
func (m *Manager) RunMonitor(ctx context.Context, interval time.Duration, defs func() []games.GameDef) {
	if m.Root == nil {
		return
	}
	check := func() {
		h := m.CheckHealth(defs())
		m.health.mu.Lock()
		prev := m.health.last
		m.health.last = h
		m.health.mu.Unlock()
		switch {
		case !h.OK && (!prev.Checked || prev.OK || strings.Join(prev.Problems, ";") != strings.Join(h.Problems, ";")):
			msg := "backups folder problem: " + strings.Join(h.Problems, "; ")
			log.Printf("backup: %s", msg)
			m.record("", "", msg)
			m.notify("⚠️ **Backups are paused.** " + msg)
		case h.OK && prev.Checked && !prev.OK:
			log.Printf("backup: backups folder is healthy again")
			m.record("", "", "backups folder is healthy again")
			m.notify("✅ The backups folder is healthy again; backups can run.")
		}
	}
	check()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}

// preflight refuses to start a backup the folder cannot hold.
func (m *Manager) preflight(d games.GameDef) error {
	if err := m.checkRoot(d); err != nil {
		return err
	}
	if d.Backup != nil && d.Backup.LocalDir != "" {
		if free, ok := freeSpace(m.Root.Mount); ok && free < m.minFree() {
			return fmt.Errorf("%w: %d MiB free (need %d MiB)", ErrLowSpace, free>>20, m.minFree()>>20)
		}
	}
	return nil
}

// refused records and announces a backup that was not started, so a scheduled
// or before-stop backup that cannot run does not fail silently.
func (m *Manager) refused(d games.GameDef, actor string, err error) {
	m.record(d.ID, actor, "refused: "+tail(err.Error()))
	if actor == "" {
		m.notify(fmt.Sprintf("Backup of **%s** was not made: %s", d.DisplayName, tail(err.Error())))
	}
}

// verifyNewFile checks that a backup that reported success left a new, non-empty
// file in dir. before is the folder's listing taken before the command ran.
func verifyNewFile(dir string, before []File, began time.Time) error {
	now, err := localFiles(dir)
	if err != nil {
		return err
	}
	seen := map[string]File{}
	for _, f := range before {
		seen[f.Name] = f
	}
	fresh := false
	for _, f := range now {
		old, had := seen[f.Name]
		if had && f.Time.Equal(old.Time) && f.Size == old.Size {
			continue
		}
		if !had && f.Time.Before(began.Add(-2*time.Second)) {
			continue
		}
		fresh = true
		if f.Size == 0 {
			return fmt.Errorf("the backup file %s is empty", f.Name)
		}
	}
	if !fresh {
		return fmt.Errorf("the backup command finished but no new file appeared in %s", dir)
	}
	return nil
}

// permissionHint adds guidance when a failed backup looks like a permissions problem.
func permissionHint(msg, dir string) string {
	if dir != "" && strings.Contains(strings.ToLower(msg), "permission denied") {
		return " (the game cannot write to its backup folder: chown it to the game's user, or set platform.backups_dir_mode to \"0777\"; folder: " + dir + ")"
	}
	return ""
}
