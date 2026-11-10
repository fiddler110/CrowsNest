package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/fiddler110/crowsnest/internal/modules"
)

const moduleUsage = `usage:
  crowsnest module check <module.yaml|dir> [--log container.log]
  crowsnest module install <https-url> [--sha256 HASH] [--yes]
  crowsnest module update <id> [--yes]
  crowsnest module remove <id>
  crowsnest module list`

// moduleTool carries what the install commands need, so tests can point them
// at a temp dir and a test server.
type moduleTool struct {
	dir    string       // modules_dir
	client *http.Client // nil = default
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
	var hash string
	yes := false
	for i := 1; i < len(args); i++ {
		switch {
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
	if err != nil {
		fmt.Fprintln(t.out, "FAIL ", err)
		return 1
	}
	return 0
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
		fmt.Fprintf(t.out, "%-16s %-20s sha256:%.12s  %s\n  from %s\n", e.ID, state, e.SHA256, e.InstalledAt.Format("2006-01-02"), e.Source)
	}
	return nil
}

// fetchAndReview downloads source and prints what the module would do.
func (t *moduleTool) fetchAndReview(source, wantHash string) ([]byte, *modules.Manifest, error) {
	body, err := modules.Fetch(context.Background(), source, t.client)
	if err != nil {
		return nil, nil, err
	}
	m, err := modules.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	fmt.Fprintf(t.out, "%s (%s)\n  %s\n  sha256 %s\n", m.Name, m.ID, m.Description, modules.Hash(body))
	return body, m, nil
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
	body, m, err := t.fetchAndReview(source, wantHash)
	if err != nil {
		return err
	}
	fmt.Fprintln(t.out, "\nThis module:")
	for _, l := range m.Review() {
		fmt.Fprintln(t.out, "  -", l)
	}
	if wantHash == "" {
		fmt.Fprintln(t.out, "\nNo --sha256 was given, so you are trusting what was just downloaded. Read the lines above.")
	}
	if !t.confirm(m.ID, yes) {
		return fmt.Errorf("not approved; nothing installed")
	}
	if _, err := modules.Install(t.dir, source, body, wantHash, replace); err != nil {
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
	body, m, err := t.fetchAndReview(e.Source, wantHash)
	if err != nil {
		return err
	}
	if m.ID != id {
		return fmt.Errorf("the source now serves module %q, not %q; refusing", m.ID, id)
	}
	if modules.Hash(body) == e.SHA256 {
		// Same bytes as approved. If the file on disk was edited, this restores it.
		fmt.Fprintln(t.out, "the source is unchanged since it was approved; restoring that copy")
		_, err = modules.Install(t.dir, e.Source, body, "", true)
		return err
	}
	var old []string
	if b, err := os.ReadFile(filepath.Join(t.dir, id, "module.yaml")); err == nil { // #nosec G304 -- id is in the lock
		if om, err := modules.Parse(bytes.NewReader(b)); err == nil {
			old = om.Review()
		}
	}
	added, removed := diffLines(old, m.Review())
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
	if _, err := modules.Install(t.dir, e.Source, body, wantHash, true); err != nil {
		return err
	}
	fmt.Fprintf(t.out, "updated %s, now pinned to sha256:%.12s. Restart CrowsNest to load it.\n", id, modules.Hash(body))
	return nil
}

// diffLines returns lines only in next (added) and only in prev (removed).
func diffLines(prev, next []string) (added, removed []string) {
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
