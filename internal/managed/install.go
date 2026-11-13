package managed

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/dockerguard"
	"github.com/fiddler110/crowsnest/internal/games"
)

// install is idempotent: it can be re-run for a half-installed game.
// installMode says how to (re)install: recreate removes any existing container
// first (its data folder is a bind mount, so nothing is lost); pull makes a
// failed pull fatal (otherwise an unreachable registry is tolerated when the
// image is already local).
type installMode struct{ recreate, pull bool }

// Enable records the game and installs it in the background: scope, image,
// container, then it joins the dashboard. It returns once the request is
// accepted; List shows the progress.
func (m *Manager) Enable(r Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.withCopy(r)
	if err != nil {
		return err
	}
	r = m.withDefaults(r)
	g, mf, err := m.validate(r, false)
	if err != nil {
		return err
	}
	rd, err := m.renderAndFit(g, mf)
	if err != nil {
		return fmt.Errorf("outside the operator's policy (add it to policy.yaml to allow it): %w", err)
	}
	e := &entry{Request: r, State: StateInstalling, rendered: rd}
	m.entries = append(m.entries, e)
	if err := m.save(); err != nil {
		m.entries = m.entries[:len(m.entries)-1]
		return err
	}
	go m.install(e, g, installMode{})
	return nil
}

func (m *Manager) install(e *entry, g config.GameConfig, mode installMode) {
	err := m.doInstall(e, g, mode)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		log.Printf("managed: installing %s failed: %v", e.ID, err)
		e.State, e.Error = StateFailed, err.Error()
	} else {
		e.State, e.Error = StateReady, ""
	}
	if serr := m.save(); serr != nil {
		log.Printf("managed: saving state: %v", serr)
	}
}

func (m *Manager) doInstall(e *entry, g config.GameConfig, mode installMode) error {
	m.mu.Lock()
	rd := e.rendered
	ref, repo, name := rd.Ref(), rd.Repo, rd.Service.ContainerName
	cur := e.pin
	err := m.writeScopes()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if name == "" {
		name = rd.ID
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	// The panel makes the game's backup folder itself: if Docker created the
	// bind source it would be root-owned, and a missing external drive would
	// look like a fresh empty folder.
	if g.Backup != nil && g.Backup.LocalDir != "" {
		if m.Backups == nil {
			return errors.New("platform.backups_root is set but the panel has no backups folder mounted")
		}
		if err := m.Backups.EnsureGameDir(rd.ID); err != nil {
			return err
		}
	}
	exists, err := m.Docker.Exists(ctx, name)
	if err != nil {
		return err
	}
	if exists && !mode.recreate {
		return m.register(e, g) // a half-finished install whose container is already there
	}
	// A pull tolerated when it fails: an edit or rollback can use the image already on the host.
	tolerant := mode.recreate && !mode.pull
	pull := func(image string) error {
		// The guard reloads on its own schedule; until it has our scope it answers 403.
		err := m.retryDenied(ctx, func() error { return m.Docker.Pull(ctx, image) })
		if err != nil && tolerant && !dockerctl.IsDenied(err) {
			log.Printf("managed: pull %s failed, using the local image: %v", image, err)
			return nil
		}
		if err != nil {
			return fmt.Errorf("pull %s: %w", image, err)
		}
		return nil
	}

	next := cur
	if mode.pull || cur.Digest == "" || cur.Image != ref {
		// Follow the tag: pull it and pin what it resolves to now.
		before := cur.Digest
		if before == "" && exists {
			before, _ = m.digestOf(ctx, ref, repo) // an install from before pinning: what the tag pointed to until now
		}
		if cur.Image != "" && cur.Image != ref && !sameRepo(cur.Image, repo) {
			before = "" // another repository: its digests mean nothing here
		}
		if err := pull(ref); err != nil {
			if exists {
				// The old container was never touched: keep the game on the dashboard as it was.
				if rerr := m.register(e, g); rerr != nil {
					log.Printf("managed: %s: %v", e.ID, rerr)
				}
			}
			return err
		}
		d, derr := m.digestOf(ctx, ref, repo)
		if derr != nil {
			log.Printf("managed: %s: no digest to pin, running the tag: %v", e.ID, derr)
		}
		next = pin{Image: ref, Digest: d, PreviousDigest: cur.PreviousDigest}
		if cur.Image != "" && !sameRepo(cur.Image, repo) {
			next.PreviousDigest = ""
		}
		if before != "" && d != "" && before != d {
			next.PreviousDigest = before
		}
		if mode.pull {
			m.mu.Lock()
			e.refresh = RefreshUpdated
			if d != "" && d == before {
				e.refresh = RefreshUpToDate // the same image (an older install is still recreated once, to pin it)
			}
			if d != "" && d == cur.Digest && exists {
				// Nothing new upstream: the container stays exactly as it is.
				e.refresh = RefreshUpToDate
				m.mu.Unlock()
				return m.register(e, g)
			}
			m.mu.Unlock()
		}
	} else if _, ierr := m.Docker.ImageDigests(ctx, repo+"@"+cur.Digest); ierr != nil {
		// Pinned, but the image is not on the host (pruned): fetch exactly that one.
		if err := pull(repo + "@" + cur.Digest); err != nil {
			return err
		}
	}

	m.mu.Lock()
	e.pin = next
	rd.Pin(next.Digest)
	spec, err := rd.Spec(m.lookup(e))
	if err == nil {
		err = m.save()
	}
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if exists {
		if err := m.Docker.Remove(ctx, name); err != nil {
			return fmt.Errorf("remove the old container: %w", err)
		}
	}
	if err := m.retryDenied(ctx, func() error { return m.Docker.Create(ctx, spec) }); err != nil {
		return fmt.Errorf("create container: %w", err)
	}
	return m.register(e, g)
}

// digestOf is the registry digest (sha256:...) the local image ref carries for repo.
func (m *Manager) digestOf(ctx context.Context, ref, repo string) (string, error) {
	list, err := m.Docker.ImageDigests(ctx, ref)
	if err != nil {
		return "", err
	}
	want, _, _, err := dockerguard.ParseImageRef(repo)
	if err != nil {
		return "", err
	}
	for _, rd := range list {
		name, d, ok := strings.Cut(rd, "@")
		if !ok || !dockerguard.IsDigest(d) {
			continue
		}
		if r, _, _, err := dockerguard.ParseImageRef(name); err == nil && r == want {
			return d, nil
		}
	}
	return "", fmt.Errorf("%s has no registry digest for %s (built locally?)", ref, repo)
}

// sameRepo reports whether the tag reference ref names repository repo.
func sameRepo(ref, repo string) bool {
	a, _, _, err1 := dockerguard.ParseImageRef(ref)
	b, _, _, err2 := dockerguard.ParseImageRef(repo)
	return err1 == nil && err2 == nil && a == b
}

func (m *Manager) retryDenied(ctx context.Context, f func() error) error {
	wait := m.Settle
	if wait == 0 {
		wait = 30 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		err := f()
		if err == nil || !dockerctl.IsDenied(err) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// lookup resolves a compose variable: the game's own secrets, then the panel's environment, but only for the
// variables this game owns (TZ, and <ID>_<OPTION> for its module's options). Anything else is unset: an option
// such as rcon_password_env, or a module's env, must not be able to name another variable of the panel's
// environment (an OAuth client secret, a webhook URL, another game's password) and have it sent to the game.
func (m *Manager) lookup(e *entry) func(string) (string, bool) {
	secrets := m.secretsFor(e)
	own := map[string]bool{"TZ": true}
	if mf, ok := m.Modules.Manifest(e.Module); ok {
		for _, o := range mf.Options {
			own[envName(e.ID, o.Key)] = true
		}
	}
	return func(name string) (string, bool) {
		if v, ok := secrets[name]; ok {
			return v, true
		}
		if !own[name] {
			return "", false
		}
		return os.LookupEnv(name)
	}
}

func (m *Manager) secretsFor(e *entry) map[string]string {
	out := map[string]string{}
	for k, v := range e.Secrets {
		out[envName(e.ID, k)] = v
	}
	return out
}

// register puts the game on the dashboard: its module's probes, runners and registry entry.
func (m *Manager) register(e *entry, g config.GameConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	find := m.lookup(e)
	lookup := func(name string) string {
		v, _ := find(name)
		return v
	}
	def, runners := m.Modules.BuildOne(m.Config, g, m.Wire, lookup)
	if mf, ok := m.Modules.Manifest(e.Module); ok {
		for _, c := range mf.Connect {
			v := e.Secrets[c.Option]
			if v == "" {
				v = e.Options[c.Option]
			}
			if v != "" {
				def.ConnectSecrets = append(def.ConnectSecrets, games.ConnectSecret{Label: c.Label, Value: v})
			}
		}
	}
	if err := m.Registry.Add(def); err != nil {
		if _, have := m.Registry.Get(g.ID); !have {
			return err
		}
		return nil // already registered (re-run)
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	rctx, cancel := context.WithCancel(ctx)
	e.stop = cancel
	for _, r := range runners {
		go r.Run(rctx)
	}
	return nil
}

// Update changes an enabled game's settings and recreates its container with
// them. The module cannot change. Secrets left out keep their stored value.
// The game must be stopped; its data folder is untouched.
func (m *Manager) Update(r Request) error { return m.reinstall(r, opEdit) }

// Refresh pulls the game's image tag again and, only if it now points at
// another image, recreates the container on that digest (the old one becomes
// the rollback target). List reports the outcome in Info.Refresh once done.
func (m *Manager) Refresh(id string) error { return m.reinstall(Request{ID: id}, opRefresh) }

// Rollback recreates a stopped game's container on its previous image digest,
// and makes the current one the previous (so a second rollback undoes it).
// ErrNoPrevious when there is none.
func (m *Manager) Rollback(id string) error { return m.reinstall(Request{ID: id}, opRollback) }

var errBusy = errors.New("the game is starting or stopping; wait for it to finish")

type reinstallOp int

const (
	opEdit reinstallOp = iota
	opRefresh
	opRollback
)

func (m *Manager) reinstall(r Request, op reinstallOp) error {
	refresh := op != opEdit
	if m.Busy != nil && m.Busy(r.ID) {
		return errBusy
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if running, err := m.Docker.Running(ctx, r.ID); err != nil {
		return err
	} else if running {
		return errors.New("stop the game before changing it")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.find(r.ID)
	if e == nil {
		return fmt.Errorf("game %q is not a dashboard-enabled game", r.ID)
	}
	if e.State == StateInstalling {
		return errors.New("the game is still installing")
	}
	if op == opRollback && (e.PreviousDigest == "" || e.Image == "") {
		return ErrNoPrevious
	}
	next := e.Request
	if !refresh {
		if r.Module != "" && r.Module != e.Module {
			return errors.New("a game's module cannot change: disable it and enable it again")
		}
		next.DisplayName, next.ConnectAddress, next.Options = r.DisplayName, r.ConnectAddress, r.Options
		next.Secrets = map[string]string{}
		for k, v := range e.Secrets {
			next.Secrets[k] = v
		}
		for k, v := range r.Secrets {
			if v != "" {
				next.Secrets[k] = v
			}
		}
	}
	g, mf, err := m.validate(next, true)
	if err != nil {
		return err
	}
	rd, err := m.renderAndFit(g, mf)
	if err != nil {
		return fmt.Errorf("outside the operator's policy (add it to policy.yaml to allow it): %w", err)
	}
	if e.stop != nil {
		e.stop()
		e.stop = nil
	}
	m.Registry.Remove(e.ID)
	e.Request, e.rendered, e.State, e.Error, e.refresh = next, rd, StateInstalling, "", ""
	if op == opRollback {
		e.Digest, e.PreviousDigest = e.PreviousDigest, e.Digest
	}
	if err := m.save(); err != nil {
		return err
	}
	go m.install(e, g, installMode{recreate: true, pull: op == opRefresh})
	return nil
}

// DisableOptions says what Disable deletes besides the game itself.
type DisableOptions struct {
	Data    bool // empty the game's data folders (a one-shot <id>-clean container)
	Backups bool // delete the game's folder in the shared backups folder
}

// Disable removes a stopped game: its container, dashboard entry, scope and
// secrets. Its data folders and backups are kept unless o says otherwise;
// when it does, they are deleted first, so a failure leaves the game listed
// and the deletion can be retried.
func (m *Manager) Disable(id string, o DisableOptions) error {
	m.mu.Lock()
	e := m.find(id)
	m.mu.Unlock()
	if e == nil {
		return fmt.Errorf("game %q is not a dashboard-enabled game", id)
	}
	if m.Busy != nil && m.Busy(id) {
		return errBusy
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	running, err := m.Docker.Running(ctx, id)
	if err != nil {
		return err
	}
	if running {
		return errors.New("stop the game before disabling it")
	}
	if o.Backups && (m.Backups == nil || m.Platform.BackupsRoot == "") {
		return errors.New("this panel has no shared backups folder, so there is nothing to delete there")
	}
	var clean dockerctl.CreateSpec
	if o.Data {
		var ok bool
		m.mu.Lock()
		if e.rendered != nil {
			clean, ok = e.rendered.CleanSpec()
		}
		m.mu.Unlock()
		if !ok || m.RunHelper == nil {
			return errors.New("this game has no data folders the panel can empty")
		}
	}
	if o.Backups {
		if err := m.Backups.Verify(); err != nil { // refuse before anything is deleted
			return err
		}
	}
	if o.Data {
		if err := m.RunHelper(ctx, clean); err != nil {
			return fmt.Errorf("emptying the data folders failed (nothing else was changed): %w", err)
		}
	}
	if ok, _ := m.Docker.Exists(ctx, id); ok {
		if err := m.Docker.Remove(ctx, id); err != nil {
			return err
		}
	}
	if o.Backups {
		if err := m.Backups.RemoveGameDir(id); err != nil {
			return fmt.Errorf("deleting the backups failed: %w", err)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.stop != nil {
		e.stop()
	}
	m.Registry.Remove(id)
	for i, x := range m.entries {
		if x == e {
			m.entries = append(m.entries[:i], m.entries[i+1:]...)
			break
		}
	}
	if err := m.writeScopes(); err != nil {
		return err
	}
	return m.save()
}
