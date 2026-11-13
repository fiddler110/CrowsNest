package gamefiles

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/atomicfile"
)

// Helper edits files of a stopped game through a one-shot container. The managed-games manager provides it; it is
// nil for games set up in config.yaml.
type Helper interface {
	// CanEditStopped reports whether the file lies inside the game's data folders, so a helper container sees it.
	CanEditStopped(game string, sp Spec) bool
	ReadStopped(ctx context.Context, game string, sp Spec) (string, error)
	WriteStopped(ctx context.Context, game string, sp Spec, content string) error
}

// Docker is the part of dockerctl.Client the service needs.
type Docker interface {
	Running(ctx context.Context, name string) (bool, error)
	ExecTimeout(ctx context.Context, name string, timeout time.Duration, args ...string) (string, error)
	ExecStdin(ctx context.Context, name string, stdin io.Reader, timeout time.Duration, args ...string) (string, error)
}

// Errors the web layer maps to status codes.
var (
	ErrUnknownFile = errors.New("this game has no such file")
	ErrTooLarge    = errors.New("the file is larger than its limit")
	ErrChanged     = errors.New("the file changed since you opened it")
	ErrNotRunning  = errors.New("the game is stopped and this file cannot be edited while it is")
)

const (
	execTimeout = 20 * time.Second
	// KeepVersions is how many earlier versions of a file the panel keeps.
	KeepVersions = 10
)

// Service reads and writes declared files and keeps each file's earlier versions in HistoryDir (panel-side, 0600,
// admin-only: these files can hold passwords).
type Service struct {
	Docker     Docker
	Helper     Helper // optional: lets a stopped game's files be edited
	HistoryDir string

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func (s *Service) lock(game, file string) func() {
	s.mu.Lock()
	if s.locks == nil {
		s.locks = map[string]*sync.Mutex{}
	}
	k := game + "/" + file
	m := s.locks[k]
	if m == nil {
		m = &sync.Mutex{}
		s.locks[k] = m
	}
	s.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// Find returns the spec with this id.
func Find(specs []Spec, id string) (Spec, bool) {
	for _, sp := range specs {
		if sp.ID == id {
			return sp, true
		}
	}
	return Spec{}, false
}

// Mode says how a file is reached right now.
type Mode int

const (
	// ModeExec: the game's container runs, so docker exec reads and writes the file.
	ModeExec Mode = iota
	// ModeHelper: the game is stopped; a one-shot helper container does it.
	ModeHelper
)

// mode picks how to reach sp for a game whose container is container.
func (s *Service) mode(ctx context.Context, game, container string, sp Spec) (Mode, error) {
	up, err := s.Docker.Running(ctx, container)
	if err != nil {
		return ModeExec, err
	}
	switch {
	case up:
		return ModeExec, nil
	case s.Helper != nil && s.Helper.CanEditStopped(game, sp):
		return ModeHelper, nil
	}
	return ModeExec, ErrNotRunning
}

// CanEditStopped reports whether a stopped game's file can be edited.
func (s *Service) CanEditStopped(game string, sp Spec) bool {
	return s.Helper != nil && s.Helper.CanEditStopped(game, sp)
}

// Read returns the file's current content and its hash. For a stopped game it uses the helper container, if the
// file is inside the game's data folders, and fails with ErrNotRunning otherwise.
func (s *Service) Read(ctx context.Context, game, container string, sp Spec) (content, hash string, err error) {
	m, err := s.mode(ctx, game, container, sp)
	if err != nil {
		return "", "", err
	}
	var out string
	if m == ModeHelper {
		out, err = s.Helper.ReadStopped(ctx, game, sp)
	} else {
		out, err = s.Docker.ExecTimeout(ctx, container, execTimeout, sp.ReadArgs()...)
	}
	if err != nil {
		return "", "", err
	}
	if len(out) > sp.MaxBytes {
		return "", "", ErrTooLarge
	}
	if err := CheckText([]byte(out)); err != nil {
		return "", "", err
	}
	return out, Hash([]byte(out)), nil
}

// Write replaces the file with content, provided it still has the hash baseHash the editor opened. The old
// version is kept in the history first. It returns the new hash. content is what the editor sent (with any mask
// still in it); the spec's redactions are undone against the current file before it is written.
func (s *Service) Write(ctx context.Context, game, container string, sp Spec, content, baseHash string) (newHash string, err error) {
	defer s.lock(game, sp.ID)()
	cur, curHash, err := s.Read(ctx, game, container, sp)
	if err != nil {
		return "", err
	}
	if curHash != baseHash {
		return "", ErrChanged
	}
	real, err := sp.Restore(strings.ReplaceAll(content, "\r\n", "\n"), cur)
	if err != nil {
		return "", err
	}
	if len(real) > sp.MaxBytes {
		return "", ErrTooLarge
	}
	if err := CheckText([]byte(real)); err != nil {
		return "", err
	}
	if real == cur {
		return curHash, nil
	}
	if err := s.keep(game, sp.ID, cur); err != nil {
		return "", fmt.Errorf("could not keep the old version, so nothing was written: %w", err)
	}
	m, err := s.mode(ctx, game, container, sp) // the game may have started or stopped while the editor was open
	if err != nil {
		return "", err
	}
	if m == ModeHelper {
		err = s.Helper.WriteStopped(ctx, game, sp, real)
	} else {
		_, err = s.Docker.ExecStdin(ctx, container, strings.NewReader(real), execTimeout, sp.WriteArgs()...)
	}
	if err != nil {
		return "", err
	}
	return Hash([]byte(real)), nil
}

// Version is one kept earlier version of a file.
type Version struct {
	ID    string    `json:"id"` // file name, safe to hand back to Get
	Time  time.Time `json:"time"`
	Bytes int       `json:"bytes"`
}

func (s *Service) dir(game, file string) string {
	return filepath.Join(s.HistoryDir, game, file)
}

func (s *Service) keep(game, file, content string) error {
	if s.HistoryDir == "" {
		return errors.New("no history folder is configured")
	}
	d := s.dir(game, file)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	name := time.Now().UTC().Format("20060102T150405.000000000Z") + ".txt"
	if err := atomicfile.Write(filepath.Join(d, name), []byte(content), 0o600); err != nil {
		return err
	}
	vs, _ := s.versions(game, file)
	for i := KeepVersions; i < len(vs); i++ { // newest first, so the tail is the oldest
		_ = os.Remove(filepath.Join(d, vs[i].ID))
	}
	return nil
}

func (s *Service) versions(game, file string) ([]Version, error) {
	ents, err := os.ReadDir(s.dir(game, file))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var vs []Version
	for _, e := range ents {
		t, err := time.Parse("20060102T150405.000000000Z", strings.TrimSuffix(e.Name(), ".txt"))
		if err != nil || e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		vs = append(vs, Version{ID: e.Name(), Time: t, Bytes: int(info.Size())})
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i].Time.After(vs[j].Time) })
	return vs, nil
}

// History lists the kept versions of a file, newest first.
func (s *Service) History(game string, sp Spec) ([]Version, error) {
	return s.versions(game, sp.ID)
}

// Version returns one kept version as stored (the web layer hides redacted values, as for the live file).
func (s *Service) Version(game string, sp Spec, id string) (string, error) {
	vs, err := s.versions(game, sp.ID)
	if err != nil {
		return "", err
	}
	for _, v := range vs { // only names we listed ourselves: id is never joined to a path unchecked
		if v.ID == id {
			b, err := os.ReadFile(filepath.Join(s.dir(game, sp.ID), v.ID)) // #nosec G304 -- v.ID came from ReadDir above
			if err != nil {
				return "", err
			}
			return string(b), nil
		}
	}
	return "", os.ErrNotExist
}
