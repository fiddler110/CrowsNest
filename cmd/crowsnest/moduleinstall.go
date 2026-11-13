package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fiddler110/crowsnest/internal/modules"
)

const moduleUsage = `usage:
  crowsnest module check <module.yaml|dir> [--log container.log]
  crowsnest module install <https-url> [--sha256 HASH] [--yes]
  crowsnest module update <id> [--yes]
  crowsnest module remove <id>
  crowsnest module list
  crowsnest module keygen <name>                       (a publisher key pair: <name>.key and the public key to share)
  crowsnest module sign <module.yaml> --key <file>     (writes <module.yaml>.sig to publish beside it)`

// moduleTool carries what the install commands need, so tests can point them
// at a temp dir and a test server.
type moduleTool struct {
	dir    string               // modules_dir
	keys   []modules.TrustedKey // managed.trusted_keys: a module signed by one is installed under that signature
	client *http.Client         // nil = default
	in     io.Reader
	out    io.Writer
}

// run handles install, update, remove and list. It returns the exit status.
func (t *moduleTool) run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(t.out, moduleUsage)
		return 2
	}
	var pos []string
	var hash, keyFile string
	yes := false
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "--key" && i+1 < len(args):
			keyFile = args[i+1]
			i++
		case args[i] == "--yes":
			yes = true
		case args[i] == "--sha256" && i+1 < len(args):
			hash = args[i+1]
			i++
		case strings.HasPrefix(args[i], "-"):
			fmt.Fprintln(t.out, moduleUsage)
			return 2
		default:
			pos = append(pos, args[i])
		}
	}
	// Publisher commands need no modules_dir.
	switch {
	case args[0] == "keygen" && len(pos) == 1:
		return t.report(t.keygen(pos[0]))
	case args[0] == "sign" && len(pos) == 1 && keyFile != "":
		return t.report(t.sign(pos[0], keyFile))
	}
	if t.dir == "" {
		fmt.Fprintln(t.out, "FAIL  modules_dir is not set in config.yaml; installed modules need a folder to live in")
		return 1
	}
	var err error
	switch {
	case args[0] == "list" && len(pos) == 0:
		err = t.list()
	case args[0] == "install" && len(pos) == 1:
		err = t.install(pos[0], hash, yes, false)
	case args[0] == "update" && len(pos) == 1:
		err = t.update(pos[0], hash, yes)
	case args[0] == "remove" && len(pos) == 1:
		if err = modules.Uninstall(t.dir, pos[0]); err == nil {
			fmt.Fprintf(t.out, "removed %s. Restart CrowsNest to apply; games using it fall back to the baseline.\n", pos[0])
		}
	default:
		fmt.Fprintln(t.out, moduleUsage)
		return 2
	}
	return t.report(err)
}

func (t *moduleTool) report(err error) int {
	if err != nil {
		fmt.Fprintln(t.out, "FAIL ", err)
		return 1
	}
	return 0
}

// keygen makes a publisher key. The seed is written to <name>.key (0600, never overwritten); the public half is
// printed with the config.yaml lines that make a CrowsNest trust it.
func (t *moduleTool) keygen(name string) error {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).MatchString(name) {
		return fmt.Errorf("%q is not a usable key name: letters, digits, . _ - only", name)
	}
	seed, pub, err := modules.GenerateKey()
	if err != nil {
		return err
	}
	path := name + ".key"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a file the operator named
	if err != nil {
		return fmt.Errorf("%s: %w (it is never overwritten)", path, err)
	}
	if _, err := f.WriteString(seed + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(t.out, "wrote %s (the secret: keep it private and backed up; whoever has it can publish modules you are trusted for)\n\n", path)
	fmt.Fprintf(t.out, "To trust this key, add under managed: in config.yaml\n  trusted_keys:\n    - {name: %s, public_key: %s}\n", name, pub)
	return nil
}

// sign writes <file>.sig, the signature a CrowsNest that trusts the key looks for beside the module's URL.
func (t *moduleTool) sign(file, keyFile string) error {
	body, err := os.ReadFile(file) // #nosec G304 -- a file the operator named
	if err != nil {
		return err
	}
	m, err := modules.Parse(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s is not a valid module, so it is not signed: %w", file, err)
	}
	seed, err := os.ReadFile(keyFile) // #nosec G304 -- a file the operator named
	if err != nil {
		return err
	}
	sig, err := modules.Sign(string(seed), body)
	if err != nil {
		return err
	}
	if err := os.WriteFile(file+modules.SigSuffix, sig, 0o644); err != nil { // #nosec G306 -- a signature is public
		return err
	}
	fmt.Fprintf(t.out, "signed %s (%s), sha256:%.12s. Publish %s%s next to it.\n", file, m.ID, modules.Hash(body), filepath.Base(file), modules.SigSuffix)
	return nil
}

func (t *moduleTool) list() error {
	l, err := modules.ReadLock(t.dir)
	if err != nil {
		return err
	}
	if len(l.Modules) == 0 {
		fmt.Fprintln(t.out, "no remote modules installed")
		return nil
	}
	for _, e := range l.Modules {
		state := "ok"
		if b, err := os.ReadFile(filepath.Join(t.dir, e.ID, "module.yaml")); err != nil { // #nosec G304 -- id from the lock
			state = "MISSING"
		} else if modules.Hash(b) != e.SHA256 {
			state = "CHANGED, not loaded"
		}
		by := ""
		if e.SignedBy != "" {
			by = "  signed by " + e.SignedBy
		}
		fmt.Fprintf(t.out, "%-16s %-20s sha256:%.12s  %s%s\n  from %s\n", e.ID, state, e.SHA256, e.InstalledAt.Format("2006-01-02"), by, e.Source)
	}
	return nil
}

// fetchAndReview downloads source (and, when trusted keys are configured, its signature) and prints what the
// module would do. by is the trusted key that signed it, "" when none did.
func (t *moduleTool) fetchAndReview(source, wantHash string) (body []byte, m *modules.Manifest, by string, err error) {
	if len(t.keys) > 0 {
		body, by, err = modules.FetchSigned(context.Background(), source, t.client, t.keys)
		if errors.Is(err, modules.ErrNotSigned) && body != nil {
			fmt.Fprintf(t.out, "not signed by a trusted key (%v)\n", err)
			err = nil
		}
	} else {
		body, err = modules.Fetch(context.Background(), source, t.client)
	}
	if err != nil {
		return nil, nil, "", err
	}
	m, err = modules.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, nil, "", err
	}
	fmt.Fprintf(t.out, "%s (%s)\n  %s\n  sha256 %s\n", m.Name, m.ID, m.Description, modules.Hash(body))
	if by != "" {
		fmt.Fprintf(t.out, "  signed by the trusted key %q\n", by)
	}
	return body, m, by, nil
}

func (t *moduleTool) confirm(id string, yes bool) bool {
	if yes {
		return true
	}
	fmt.Fprintf(t.out, "\nType the module id (%s) to approve it, anything else cancels: ", id)
	line, _ := bufio.NewReader(t.in).ReadString('\n')
	return strings.TrimSpace(line) == id
}

func (t *moduleTool) install(source, wantHash string, yes, replace bool) error {
	body, m, by, err := t.fetchAndReview(source, wantHash)
	if err != nil {
		return err
	}
	fmt.Fprintln(t.out, "\nThis module:")
	for _, l := range m.Review() {
		fmt.Fprintln(t.out, "  -", l)
	}
	if wantHash == "" && by == "" {
		fmt.Fprintln(t.out, "\nNo --sha256 was given and no trusted key signed it, so you are trusting what was just downloaded. Read the lines above.")
	}
	if !t.confirm(m.ID, yes) {
		return fmt.Errorf("not approved; nothing installed")
	}
	if _, err := modules.Install(t.dir, source, body, wantHash, replace, by); err != nil {
		return err
	}
	fmt.Fprintf(t.out, "installed %s, pinned to sha256:%.12s. Restart CrowsNest to load it.\n", m.ID, modules.Hash(body))
	return nil
}

func (t *moduleTool) update(id, wantHash string, yes bool) error {
	l, err := modules.ReadLock(t.dir)
	if err != nil {
		return err
	}
	e, ok := l.Find(id)
	if !ok {
		return fmt.Errorf("%q was not installed by crowsnest", id)
	}
	body, m, by, err := t.fetchAndReview(e.Source, wantHash)
	if err != nil {
		return err
	}
	if e.SignedBy != "" && by == "" && wantHash == "" {
		return fmt.Errorf("%q was installed under a signature from %q and this version is not signed by a trusted key; refusing (to trust a different source of it, remove the module and install it again)", id, e.SignedBy)
	}
	if m.ID != id {
		return fmt.Errorf("the source now serves module %q, not %q; refusing", m.ID, id)
	}
	if err := modules.CheckUpdate(e, m, body, by); err != nil {
		return err
	}
	if modules.Hash(body) == e.SHA256 {
		// Same bytes as approved. If the file on disk was edited, this restores it.
		fmt.Fprintln(t.out, "the source is unchanged since it was approved; restoring that copy")
		_, err = modules.Install(t.dir, e.Source, body, "", true, by)
		return err
	}
	var old []string
	if b, err := os.ReadFile(filepath.Join(t.dir, id, "module.yaml")); err == nil { // #nosec G304 G703 -- id is in the lock
		if om, err := modules.Parse(bytes.NewReader(b)); err == nil {
			old = om.Review()
		}
	}
	added, removed := modules.DiffLines(old, m.Review())
	fmt.Fprintf(t.out, "\nChanged since you approved it (was sha256:%.12s):\n", e.SHA256)
	for _, l := range removed {
		fmt.Fprintln(t.out, "  - no longer:", l)
	}
	for _, l := range added {
		fmt.Fprintln(t.out, "  + now:      ", l)
	}
	if len(added)+len(removed) == 0 {
		fmt.Fprintln(t.out, "  (nothing in the capability summary changed; startup, probe or text details did, so read the diff of the file if unsure)")
	}
	if !t.confirm(id, yes) {
		return fmt.Errorf("not approved; the old version stays")
	}
	if _, err := modules.Install(t.dir, e.Source, body, wantHash, true, by); err != nil {
		return err
	}
	fmt.Fprintf(t.out, "updated %s, now pinned to sha256:%.12s. Restart CrowsNest to load it.\n", id, modules.Hash(body))
	return nil
}
