package backup

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrRootUnavailable means the shared backups folder cannot be trusted right
// now: it is not writable, or it is not the folder CrowsNest used before.
var ErrRootUnavailable = errors.New("backup: the backups folder is unavailable")

const markerName = ".crowsnest-backups"

// Root is the shared backups folder as the panel sees it, one sub-folder per
// game. Its guard against a missing drive: Docker creates an empty host folder
// when a bind source is absent, so an unmounted external drive looks like a
// fresh empty backups folder. Root puts a marker file (a random token) in the
// folder and remembers the same token in StateFile, which lives on the panel's
// own data volume. A folder that no longer carries the remembered token is
// refused instead of being quietly treated as new.
type Root struct {
	Mount     string      // where the panel sees the folder, e.g. /game-backups
	Mode      os.FileMode // permission bits for each game's folder
	StateFile string      // remembers the marker token; "" skips the check (tests)
	// ConfirmNew is the operator's statement that a folder with no marker and
	// no remembered token is the right one. Without it such a folder is refused.
	ConfirmNew bool
}

func readToken(path string) string {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured paths
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Verify checks the folder is writable and is the one used before.
func (r *Root) Verify() error {
	fi, err := os.Stat(r.Mount)
	if err != nil || !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a folder in the panel (is it mounted?)", ErrRootUnavailable, r.Mount)
	}
	marker := filepath.Join(r.Mount, markerName)
	onDisk := readToken(marker)
	if r.StateFile == "" {
		return nil
	}
	known := readToken(r.StateFile)
	switch {
	case known != "" && onDisk != known:
		return fmt.Errorf("%w: %s no longer carries the marker CrowsNest left there (an unmounted drive shows up as an empty folder). "+
			"If you moved the backups on purpose, delete %s and restart", ErrRootUnavailable, r.Mount, r.StateFile)
	case known == "" && onDisk == "" && !r.ConfirmNew:
		return fmt.Errorf("%w: CrowsNest has not used %s before and it holds no marker. An unmounted drive looks exactly like this. "+
			"Once you have checked the right drive is mounted there, set platform.backups_confirm_new: true and restart",
			ErrRootUnavailable, r.Mount)
	case known == "" && onDisk == "":
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return err
		}
		onDisk = hex.EncodeToString(b[:])
		if err := os.WriteFile(marker, []byte(onDisk+"\n"), 0o644); err != nil { // #nosec G306 -- a marker, not a secret
			return fmt.Errorf("%w: %s is not writable by CrowsNest: %v", ErrRootUnavailable, r.Mount, err)
		}
		fallthrough
	case known == "":
		// First use, or an existing backups drive adopted by a fresh panel.
		if err := os.WriteFile(r.StateFile, []byte(onDisk+"\n"), 0o600); err != nil {
			return fmt.Errorf("%w: cannot remember the backups folder in %s: %v", ErrRootUnavailable, r.StateFile, err)
		}
	}
	return nil
}

// EnsureGameDir verifies the root and creates <mount>/<id> with the configured
// mode (chmod'd explicitly, since the process umask would trim it). It does
// nothing to an existing folder's contents.
func (r *Root) EnsureGameDir(id string) error {
	if err := r.Verify(); err != nil {
		return err
	}
	dir := filepath.Join(r.Mount, id)
	if err := os.MkdirAll(dir, r.Mode); err != nil {
		return fmt.Errorf("%w: creating %s: %v", ErrRootUnavailable, dir, err)
	}
	if err := os.Chmod(dir, r.Mode); err != nil {
		return fmt.Errorf("%w: setting the mode of %s: %v", ErrRootUnavailable, dir, err)
	}
	return nil
}

// localFiles lists the regular files directly inside dir, newest first. It
// never follows a link: a game can write anything into its own folder, so a
// symlink there is ignored rather than trusted.
func localFiles(dir string) ([]File, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, err
	}
	var files []File
	for _, e := range entries {
		fi, err := root.Lstat(e.Name())
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		files = append(files, File{Name: e.Name(), Size: fi.Size(), Time: fi.ModTime().UTC()})
	}
	sort.Slice(files, func(i, j int) bool {
		if !files[i].Time.Equal(files[j].Time) {
			return files[i].Time.After(files[j].Time)
		}
		return files[i].Name > files[j].Name
	})
	return files, nil
}

// pruneLocal deletes all but the newest keep regular files in dir and returns
// how many it removed. Subfolders and links are left alone.
func pruneLocal(dir string, keep int) (int, error) {
	files, err := localFiles(dir)
	if err != nil || len(files) <= keep {
		return 0, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	removed := 0
	for _, f := range files[keep:] {
		if err := root.Remove(f.Name); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
