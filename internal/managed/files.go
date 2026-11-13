package managed

import (
	"context"
	"errors"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/gamefiles"
)

// The Manager lets the files service edit a stopped dashboard game's declared files through a one-shot container
// of the game's own image and data folders (guard scope <id>-files). It implements gamefiles.Helper.
var _ gamefiles.Helper = (*Manager)(nil)

type specOK struct {
	dockerctl.CreateSpec
	ok bool
}

func (m *Manager) fileSpec(id string, sp gamefiles.Spec, write bool, content string) specOK {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.ID == id && e.rendered != nil {
			s, ok := e.rendered.FileSpec(sp, write, content)
			return specOK{s, ok}
		}
	}
	return specOK{}
}

// CanEditStopped reports whether the file of game id can be reached with the game stopped.
func (m *Manager) CanEditStopped(id string, sp gamefiles.Spec) bool {
	return m.RunHelperOutput != nil && m.fileSpec(id, sp, false, "").ok
}

var errHelperBusy = errors.New("the game is starting or stopping; try again in a moment")

func (m *Manager) runFileHelper(ctx context.Context, id string, sp gamefiles.Spec, write bool, content string, maxOut int64) (string, error) {
	if m.RunHelperOutput == nil {
		return "", gamefiles.ErrNotRunning
	}
	s := m.fileSpec(id, sp, write, content)
	if !s.ok {
		return "", gamefiles.ErrNotRunning
	}
	if m.Busy != nil && m.Busy(id) {
		return "", errHelperBusy
	}
	m.fileMu.Lock()
	defer m.fileMu.Unlock()
	return m.RunHelperOutput(ctx, s.CreateSpec, maxOut)
}

// ReadStopped returns the file's content.
func (m *Manager) ReadStopped(ctx context.Context, id string, sp gamefiles.Spec) (string, error) {
	return m.runFileHelper(ctx, id, sp, false, "", int64(sp.MaxBytes)+1)
}

// WriteStopped replaces the file with content.
func (m *Manager) WriteStopped(ctx context.Context, id string, sp gamefiles.Spec, content string) error {
	_, err := m.runFileHelper(ctx, id, sp, true, content, 0)
	return err
}
