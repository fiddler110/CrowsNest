// Package managed lets the dashboard enable, configure and remove game servers
// from the module catalogue, inside the operator's policy envelope.
//
// An enabled game is rendered from its module (the same render that backs
// `crowsnest render`), checked against the operator's policy.yaml, written into
// the managed scopes file the guard watches, and then created through the
// guard. The guard enforces the policy itself on what it loads, so this
// package's check is the friendly early answer, not the security boundary.
//
// State lives in one directory the panel can write and the operator's policy
// cannot be reached from: games.json (what is enabled), secrets.json (mode
// 0600, secret option values, never written to a rendered file) and
// scopes.json (read by the guard).
package managed

import (
	"context"
	"errors"
	"github.com/fiddler110/crowsnest/internal/vault"
	"regexp"
	"sync"
	"time"

	"github.com/fiddler110/crowsnest/internal/backup"
	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/modules"
)

// Docker is the part of the engine client the manager uses.
type Docker interface {
	Create(ctx context.Context, s dockerctl.CreateSpec) error
	Pull(ctx context.Context, image string) error
	Remove(ctx context.Context, name string) error
	Exists(ctx context.Context, name string) (bool, error)
	Running(ctx context.Context, name string) (bool, error)
	// ImageDigests is a local image's RepoDigests ("repo@sha256:...").
	ImageDigests(ctx context.Context, image string) ([]string, error)
}

// Manager owns the dashboard-enabled games.
type Manager struct {
	Dir string // state directory
	// Vault encrypts secrets.json; nil leaves values as they are (tests).
	Vault      *vault.Vault
	PolicyFile string // operator's policy.yaml
	// PolicyEditable lets SetPolicy rewrite PolicyFile (the operator mounted it writable and opted in).
	PolicyEditable bool
	Platform       modules.Platform
	// Backups is the panel's view of the shared backups folder; each game's
	// folder is created in it before the container is. Needed when
	// Platform.BackupsRoot is set.
	Backups  *backup.Root
	Modules  *modules.Set
	Config   *config.Config
	Docker   Docker
	Wire     *dockerctl.Client // for module wiring (status, logs, exec)
	Registry *games.Registry
	// Settle is how long a new game waits for the guard to pick up its scope.
	Settle time.Duration
	// Busy, when set, reports a game that is mid start/stop. A start still
	// pulling has no container yet, so Docker.Running alone would miss it.
	Busy func(id string) bool
	// RunHelper runs a one-shot container to completion (the data cleaner);
	// needed only for Disable with DisableOptions.Data.
	RunHelper func(ctx context.Context, spec dockerctl.CreateSpec) error
	// RunHelperOutput is RunHelper that also returns what the container printed (up to the limit); needed to read
	// a declared file of a stopped game.
	RunHelperOutput func(ctx context.Context, spec dockerctl.CreateSpec, maxOut int64) (string, error)

	fileMu sync.Mutex // one files helper at a time: they share a container name per game

	mu      sync.Mutex
	ctx     context.Context
	entries []*entry
}

type entry struct {
	Request
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	pin

	rendered *modules.Rendered
	stop     context.CancelFunc
	refresh  string // outcome of the last image update: RefreshUpdated or RefreshUpToDate
}

// pin is the exact image a game runs. A game is pulled by tag, and the digest
// that tag resolved to is what its container is created from, so an upstream
// push changes nothing until the operator presses Update image. The digest
// before the last change is kept for a rollback.
type pin struct {
	Image          string `json:"image,omitempty"` // repo:tag the digest was resolved from
	Digest         string `json:"digest,omitempty"`
	PreviousDigest string `json:"previous_digest,omitempty"`
}

// Outcomes of an image update, as Info.Refresh reports them.
const (
	RefreshUpdated  = "updated"
	RefreshUpToDate = "up_to_date"
)

// ErrNoPrevious is a rollback with nothing to go back to.
var ErrNoPrevious = errors.New("there is no previous image to roll back to")

// Request is what the dashboard sends to enable a game.
type Request struct {
	ID             string            `json:"id"`
	Module         string            `json:"module"`
	DisplayName    string            `json:"display_name,omitempty"`
	ConnectAddress string            `json:"connect_address,omitempty"`
	Options        map[string]string `json:"options,omitempty"`
	// Secrets holds the values of the module's secret options. They are kept
	// in secrets.json and never appear in a plan, a rendered file or a list.
	Secrets map[string]string `json:"secrets,omitempty"`
	// CopyFrom names an enabled game of the same module whose secrets fill any this request leaves out, so a
	// profile made from it needs no retyping of join passwords. Only the dashboard sends it; it is never stored.
	CopyFrom string `json:"copy_from,omitempty"`

	probe bool // set by the catalogue's fit check: judge the policy only
}

// Info is a managed game as the dashboard lists it.
type Info struct {
	ID     string `json:"id"`
	Module string `json:"module"`
	State  string `json:"state"` // installing, ready, failed
	Error  string `json:"error,omitempty"`
	// What the edit form pre-fills. Secret values are never listed.
	DisplayName    string            `json:"display_name,omitempty"`
	ConnectAddress string            `json:"connect_address,omitempty"` // only what was typed in the form
	Connect        string            `json:"connect,omitempty"`         // what players use: typed, or worked out from the published port
	Options        map[string]string `json:"options,omitempty"`
	// Image is the tag the game follows (repo:tag); Digest is the exact image it
	// runs (empty for a game installed before pinning, until its next update);
	// PreviousDigest is what Rollback goes back to.
	Image          string `json:"image,omitempty"`
	Digest         string `json:"digest,omitempty"`
	PreviousDigest string `json:"previous_digest,omitempty"`
	// Refresh is how the last Update image ended: "updated" or "up_to_date".
	Refresh string `json:"refresh,omitempty"`
}

// Plan is the dry-run of a Request.
type Plan struct {
	Service string   `json:"service"` // the compose service
	Scope   string   `json:"scope"`   // the guard scope
	Env     []string `json:"env"`     // .env variables the service reads
	Fits    bool     `json:"fits"`    // inside the operator's policy
	Reason  string   `json:"reason,omitempty"`
	// The plain-language summary the dashboard shows beside the form.
	Container string   `json:"container,omitempty"`
	Image     string   `json:"image,omitempty"`
	Ports     []string `json:"ports,omitempty"`   // host_ip:port/proto -> container
	Connect   string   `json:"connect,omitempty"` // what players type to join
	Folders   []string `json:"folders,omitempty"` // host folders the game stores data in
	Memory    string   `json:"memory,omitempty"`
	// Pinning says how the image is held still: the tag is resolved to a digest on install.
	Pinning string `json:"pinning,omitempty"`
	// Setup is what the operator has to do on the host for this game, in order.
	Setup []SetupStep `json:"setup,omitempty"`
}

// SetupStep is one host-side step the dashboard cannot do for the operator.
type SetupStep struct {
	Title   string `json:"title"`
	Detail  string `json:"detail,omitempty"`
	Command string `json:"command,omitempty"` // text to copy
	Done    *bool  `json:"done,omitempty"`    // known to be done (nil = cannot be told from here)
}

const (
	StateInstalling = "installing"
	StateReady      = "ready"
	StateFailed     = "failed"
)

var (
	idRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	tagRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	reserve = map[string]bool{"image": true, "tag": true, "ports": true, "data_dir": true, "ram": true}
)

// backupFor is the module's backup block for game id. With a shared backups
// folder and a module that names a backup dir, the panel reads that game's own
// folder (<backups_root>/<id>) instead of listing through docker exec.
// RestoreSpec is the one-shot container that restores file into game id, or
// false when the game is not a dashboard game or its module cannot restore.
func (m *Manager) RestoreSpec(id, file string) (dockerctl.CreateSpec, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.ID == id && e.rendered != nil {
			return e.rendered.RestoreSpec(file)
		}
	}
	return dockerctl.CreateSpec{}, false
}

func (m *Manager) backupFor(mf *modules.Manifest, id string) *config.BackupConfig {
	if mf.Backup == nil {
		return nil
	}
	b := *mf.Backup
	if mf.Backup.Dir != "" && m.Platform.BackupsRoot != "" {
		b.LocalDir = m.Platform.BackupLocalDir(id)
	}
	return &b
}

func (m *Manager) find(id string) *entry {
	for _, e := range m.entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// ---- persistence
