package modules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LockFileName is the record of installed remote modules, kept in modules_dir.
// A module listed here is loaded only while its module.yaml still has the
// recorded hash; edit or swap the file and it stays out until it is approved
// again. Modules placed in modules_dir by hand are not listed and load as before.
const LockFileName = "modules.lock.json"

// MaxModuleBytes caps a downloaded manifest. Real ones are a few KiB.
const MaxModuleBytes = 256 << 10

// LockEntry is one installed remote module.
type LockEntry struct {
	// SignedBy names the trusted key whose signature the module was installed under, "" for a hash pin only.
	SignedBy    string    `json:"signed_by,omitempty"`
	ID          string    `json:"id"`
	Source      string    `json:"source"`
	SHA256      string    `json:"sha256"`
	InstalledAt time.Time `json:"installed_at"`
}

// Lock is the parsed lock file.
type Lock struct {
	Modules []LockEntry `json:"modules"`
}

// Hash is the hex SHA-256 of a manifest's bytes.
func Hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ReadLock loads dir's lock file. A missing file is an empty lock.
func ReadLock(dir string) (*Lock, error) {
	b, err := os.ReadFile(filepath.Join(dir, LockFileName)) // #nosec G304 -- dir is the operator-set modules_dir
	if os.IsNotExist(err) {
		return &Lock{}, nil
	}
	if err != nil {
		return nil, err
	}
	var l Lock
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", LockFileName, err)
	}
	return &l, nil
}

// Find returns the entry for id.
func (l *Lock) Find(id string) (LockEntry, bool) {
	for _, e := range l.Modules {
		if e.ID == id {
			return e, true
		}
	}
	return LockEntry{}, false
}

func (l *Lock) set(e LockEntry) {
	for i := range l.Modules {
		if l.Modules[i].ID == e.ID {
			l.Modules[i] = e
			return
		}
	}
	l.Modules = append(l.Modules, e)
	sort.Slice(l.Modules, func(i, j int) bool { return l.Modules[i].ID < l.Modules[j].ID })
}

func (l *Lock) remove(id string) {
	out := l.Modules[:0]
	for _, e := range l.Modules {
		if e.ID != id {
			out = append(out, e)
		}
	}
	l.Modules = out
}

func (l *Lock) write(dir string) error {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, LockFileName), append(b, '\n'))
}

func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil { // #nosec G302 -- readable by the panel's group, not world
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// verifyLocked reports the locked modules under dir whose manifest no longer
// matches its recorded hash (or is gone), keyed by id with the reason.
func verifyLocked(dir string) (map[string]string, error) {
	l, err := ReadLock(dir)
	if err != nil {
		return nil, err
	}
	bad := map[string]string{}
	for _, e := range l.Modules {
		b, err := os.ReadFile(filepath.Join(dir, e.ID, "module.yaml")) // #nosec G304 -- id was validated at install
		switch {
		case err != nil:
			bad[e.ID] = "its module.yaml is missing"
		case Hash(b) != e.SHA256:
			bad[e.ID] = "its module.yaml changed since it was approved (re-run `crowsnest module install` to review it)"
		}
	}
	return bad, nil
}

// Fetch downloads a manifest. Only https is accepted, redirects included, the
// body is capped, and nothing is parsed or run here.
func Fetch(ctx context.Context, rawURL string, client *http.Client) ([]byte, error) {
	return fetchCapped(ctx, rawURL, client, MaxModuleBytes)
}

// maxSigBytes caps a signature file: a base64 ed25519 signature is 88 characters.
const maxSigBytes = 1 << 10

// FetchSigned downloads a manifest and its signature (<url>.sig) and says which trusted key signed it. A module
// with no signature file, or none a trusted key made, is an error wrapping ErrNotSigned (the body is still
// returned so a caller can offer a hash-pinned install instead).
func FetchSigned(ctx context.Context, rawURL string, client *http.Client, keys []TrustedKey) (body []byte, signedBy string, err error) {
	body, err = Fetch(ctx, rawURL, client)
	if err != nil {
		return nil, "", err
	}
	sig, err := fetchCapped(ctx, rawURL+SigSuffix, client, maxSigBytes)
	if err != nil {
		return body, "", fmt.Errorf("%w: no signature at %s (%v)", ErrNotSigned, rawURL+SigSuffix, err)
	}
	by, err := VerifySignature(keys, body, sig)
	if err != nil {
		return body, "", err
	}
	return body, by, nil
}

func fetchCapped(ctx context.Context, rawURL string, client *http.Client, limit int) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("not a valid URL: %q", rawURL)
	}
	if u.Scheme != "https" {
		return nil, errors.New("only https:// sources are accepted")
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("refusing a redirect away from https")
		}
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req) // #nosec G107 -- the operator typed this URL; https only, body capped
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("download is larger than %d KiB", limit>>10)
	}
	return b, nil
}

// Review is what installing a module would let it do, in plain lines, for the
// operator to read before approving.
func (m *Manifest) Review() []string {
	var out []string
	add := func(f string, a ...any) { out = append(out, fmt.Sprintf(f, a...)) }
	tag := m.Runtime.Tag
	if tag == "" {
		tag = "latest"
	}
	add("runs the container image  %s:%s", m.Runtime.Image, tag)
	for _, p := range m.Runtime.Ports {
		proto := p.Proto
		if proto == "" {
			proto = "udp"
		}
		add("publishes %s port %d", proto, p.Port)
	}
	for _, e := range m.Runtime.Env {
		add("sets container env  %s", e)
	}
	for _, o := range m.Runtime.SecOpts {
		add("adds security option  %s  (loosens container isolation)", o)
	}
	if m.Runtime.Memory != "" || m.Runtime.RAM != "" {
		add("memory: limit %q, typical %q", m.Runtime.Memory, m.Runtime.RAM)
	}
	if m.Backup != nil && len(m.Backup.Exec) > 0 {
		add("runs inside the game's container for backups  %s", strings.Join(m.Backup.Exec, " "))
		if m.Backup.Dir != "" {
			add("gets its own folder under the shared backups folder, mounted at %s", m.Backup.Dir)
		}
		if m.Backup.Keep > 0 {
			add("deletes all but the newest %d files in %s after each backup", m.Backup.Keep, m.Backup.ExecListDir())
		}
	}
	if m.Backup != nil && len(m.Backup.Restore) > 0 {
		add("restores a backup with a one-shot container of its image, with its data folders and backups folder, running  %s", strings.Join(m.Backup.Restore, " "))
	}
	for _, a := range m.Actions {
		add("adds the admin action %q", a.ID)
	}
	if len(m.PreStop) > 0 {
		add("calls %d request(s) before it stops the game", len(m.PreStop))
	}
	if m.RCON.Addr != "" {
		add("opens an RCON console at %s", m.RCON.Addr)
	}
	if m.API.BaseURL != "" {
		add("talks to the game's HTTP API at %s", m.API.BaseURL)
	}
	if m.Players.Type == "source_rcon" {
		add("polls players with the RCON command %q at %s", m.Players.Command, m.Players.Addr)
	}
	for _, h := range m.HostSetup {
		if h.Command != "" {
			add("asks you to run on the host  %s", h.Command)
		}
	}
	return out
}

// Install writes an approved manifest into dir and records it in the lock. The
// caller has already shown Review and obtained approval; if wantHash is set it
// must equal the body's hash. A bundled id may not be replaced. replace says
// the id may already be installed (an update). signedBy is the trusted key the
// caller verified, recorded in the lock; "" when the install rests on a hash alone.
func Install(dir, source string, body []byte, wantHash string, replace bool, signedBy string) (*Manifest, error) {
	got := Hash(body)
	if wantHash != "" && !strings.EqualFold(wantHash, got) {
		return nil, fmt.Errorf("hash mismatch: expected %s, the download is %s", wantHash, got)
	}
	m, err := Parse(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for _, id := range Bundled().IDs() {
		if id == m.ID {
			return nil, fmt.Errorf("%q is a bundled module and cannot be replaced", m.ID)
		}
	}
	l, err := ReadLock(dir)
	if err != nil {
		return nil, err
	}
	_, locked := l.Find(m.ID)
	_, exists := os.Stat(filepath.Join(dir, m.ID, "module.yaml"))
	if exists == nil && !locked {
		return nil, fmt.Errorf("%s/%s/module.yaml exists and was not installed by crowsnest; move it away first", dir, m.ID)
	}
	if locked && !replace {
		return nil, fmt.Errorf("module %q is already installed; use update to replace it", m.ID)
	}
	if err := writeAtomic(filepath.Join(dir, m.ID, "module.yaml"), body); err != nil {
		return nil, err
	}
	l.set(LockEntry{ID: m.ID, Source: source, SHA256: got, SignedBy: signedBy, InstalledAt: time.Now().UTC().Truncate(time.Second)})
	if err := l.write(dir); err != nil {
		return nil, err
	}
	return m, nil
}

// Uninstall removes a module that Install put there.
func Uninstall(dir, id string) error {
	if !idRe.MatchString(id) {
		return fmt.Errorf("%q is not a module id", id)
	}
	l, err := ReadLock(dir)
	if err != nil {
		return err
	}
	if _, ok := l.Find(id); !ok {
		return fmt.Errorf("%q was not installed by crowsnest (it is not in %s)", id, LockFileName)
	}
	if err := os.RemoveAll(filepath.Join(dir, id)); err != nil {
		return err
	}
	l.remove(id)
	return l.write(dir)
}

// DiffLines returns the Review lines only in next (added) and only in prev (removed): what an update changes in
// what the module may do.
func DiffLines(prev, next []string) (added, removed []string) {
	has := func(s []string, x string) bool {
		for _, v := range s {
			if v == x {
				return true
			}
		}
		return false
	}
	for _, l := range next {
		if !has(prev, l) {
			added = append(added, l)
		}
	}
	for _, l := range prev {
		if !has(next, l) {
			removed = append(removed, l)
		}
	}
	return
}
