package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/fiddler110/crowsnest/internal/atomicfile"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/config"
)

const stateUsage = `usage:
  crowsnest state export [-o <file.tar.gz>]         snapshot the panel's own state (users, settings, activity log, games, module lock)
  crowsnest state restore <file.tar.gz> [--force]   put a snapshot back (stop the panel first; --force overwrites existing files)

The snapshot does NOT contain the vault key (master.key, or the CROWSNEST_MASTER_KEY value) or the session secret.
Sealed files in it (sign-in secrets, authenticator apps, game passwords) are unreadable without the vault key, so keep
that key somewhere else, separately from the snapshot. Signed-in browsers are simply asked to sign in again.`

// stateGroup is one place the panel keeps state. Archive names are <group>/<file>; the group says where on the host
// a file belongs, so a restore never trusts a path from the archive.
type stateGroup struct {
	name string
	dir  string
	// only lists the exact file names taken from dir. deep takes the module lock and every <id>/module.yaml instead.
	only []string
	deep bool
}

func stateGroups(cfg *config.Config) []stateGroup {
	g := []stateGroup{
		{name: "users", dir: filepath.Dir(cfg.UsersFile), only: []string{filepath.Base(cfg.UsersFile)}},
		{name: "settings", dir: filepath.Dir(cfg.Server.SettingsFile), only: []string{
			filepath.Base(cfg.Server.SettingsFile), "auth.json", "auth-prefs.json", "mfa.json", "oidc.json", "profiles.json"}},
		{name: "history", dir: filepath.Dir(cfg.Server.HistoryFile), only: []string{filepath.Base(cfg.Server.HistoryFile)}},
	}
	g = append(g, stateGroup{name: "audit", dir: filepath.Dir(cfg.Server.AuditFile), only: []string{filepath.Base(cfg.Server.AuditFile)}})
	if cfg.Managed.Dir != "" {
		g = append(g, stateGroup{name: "managed", dir: cfg.Managed.Dir, only: []string{"games.json", "secrets.json"}})
	}
	if cfg.ModulesDir != "" {
		g = append(g, stateGroup{name: "modules", dir: cfg.ModulesDir, deep: true})
	}
	return g
}

var moduleStateRe = regexp.MustCompile(`^(modules\.lock\.json|[a-z0-9][a-z0-9-]*/module\.yaml)$`)

// stateExport writes the snapshot to out and returns the archive names it holds.
func stateExport(cfg *config.Config, out io.Writer) ([]string, error) {
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	var added []string
	add := func(name, file string) error {
		info, err := os.Stat(file)
		if errors.Is(err, fs.ErrNotExist) || (err == nil && !info.Mode().IsRegular()) {
			return nil
		}
		if err != nil {
			return err
		}
		b, err := os.ReadFile(file) // #nosec G304 -- a path from the operator's own config
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: info.ModTime()}); err != nil {
			return err
		}
		if _, err := tw.Write(b); err != nil {
			return err
		}
		added = append(added, name)
		return nil
	}
	for _, g := range stateGroups(cfg) {
		if g.deep {
			err := filepath.WalkDir(g.dir, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				rel, _ := filepath.Rel(g.dir, p)
				rel = filepath.ToSlash(rel)
				if !moduleStateRe.MatchString(rel) {
					return nil
				}
				return add(g.name+"/"+rel, p)
			})
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
			continue
		}
		for _, f := range g.only {
			if err := add(g.name+"/"+f, filepath.Join(g.dir, f)); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	sort.Strings(added)
	return added, nil
}

// stateTarget maps an archive name to the file it restores, or "" when the name is not one the panel owns.
func stateTarget(cfg *config.Config, name string) string {
	group, rel, ok := strings.Cut(name, "/")
	if !ok || path.Clean(rel) != rel || strings.HasPrefix(rel, "/") || strings.Contains(rel, "..") {
		return ""
	}
	for _, g := range stateGroups(cfg) {
		if g.name != group {
			continue
		}
		if g.deep {
			if moduleStateRe.MatchString(rel) {
				return filepath.Join(g.dir, filepath.FromSlash(rel))
			}
			return ""
		}
		for _, f := range g.only {
			if f == rel {
				return filepath.Join(g.dir, f)
			}
		}
	}
	return ""
}

// stateRestore writes the snapshot's files back. An existing file is kept unless force is set. Nothing is written
// until the whole archive has been read and every name checked.
func stateRestore(cfg *config.Config, in io.Reader, force bool, out io.Writer) error {
	gz, err := gzip.NewReader(in)
	if err != nil {
		return fmt.Errorf("not a state snapshot: %w", err)
	}
	tr := tar.NewReader(gz)
	type item struct {
		dest string
		data []byte
	}
	var items []item
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading the snapshot: %w", err)
		}
		dest := stateTarget(cfg, h.Name)
		if dest == "" || h.Typeflag != tar.TypeReg {
			return fmt.Errorf("the snapshot holds %q, which this panel does not restore; refusing the whole snapshot", h.Name)
		}
		b, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			return err
		}
		items = append(items, item{dest, b})
	}
	if len(items) == 0 {
		return errors.New("the snapshot is empty")
	}
	if !force {
		for _, it := range items {
			if _, err := os.Stat(it.dest); err == nil {
				return fmt.Errorf("%s already exists; stop the panel and pass --force to overwrite it", it.dest)
			}
		}
	}
	for _, it := range items {
		if err := os.MkdirAll(filepath.Dir(it.dest), 0o750); err != nil {
			return err
		}
		if err := atomicfile.Write(it.dest, it.data, 0o600); err != nil {
			return err
		}
		fmt.Fprintln(out, "restored", it.dest)
	}
	return nil
}

func runState(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(stateUsage)
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return fmt.Errorf("config does not load: %w", err)
	}
	switch args[0] {
	case "export":
		dest := fmt.Sprintf("crowsnest-state-%s.tar.gz", time.Now().Format("20060102-150405"))
		if len(args) == 3 && args[1] == "-o" {
			dest = args[2]
		} else if len(args) != 1 {
			return errors.New(stateUsage)
		}
		f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- chosen by the operator
		if err != nil {
			return err
		}
		names, err := stateExport(cfg, f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(dest)
			return err
		}
		fmt.Fprintf(out, "wrote %s (%d files)\n", dest, len(names))
		for _, n := range names {
			fmt.Fprintln(out, "  ", n)
		}
		fmt.Fprintln(out, "Not included: the vault key and session secret. Keep the vault key (master.key or CROWSNEST_MASTER_KEY) separately; sealed files in this snapshot need it.")
		return nil
	case "restore":
		force := false
		var file string
		for _, a := range args[1:] {
			switch {
			case a == "--force":
				force = true
			case file == "" && !strings.HasPrefix(a, "-"):
				file = a
			default:
				return errors.New(stateUsage)
			}
		}
		if file == "" {
			return errors.New(stateUsage)
		}
		f, err := os.Open(file) // #nosec G304 -- chosen by the operator
		if err != nil {
			return err
		}
		defer f.Close()
		return stateRestore(cfg, f, force, out)
	}
	return errors.New(stateUsage)
}
