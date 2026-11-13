// Package atomicfile replaces a file so that a reader, or a power cut, sees either the old content or the new,
// never a truncated or empty file. The panel's users, sessions, settings, secrets and lock files all use it.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write puts data at path with permissions mode. It writes a temporary file in the same folder, syncs it to disk,
// renames it over path and then syncs the folder, so the rename itself survives a crash.
func Write(path string, data []byte, mode os.FileMode) error {
	return WriteFunc(path, mode, func(f *os.File) error {
		_, err := f.Write(data)
		return err
	})
}

// WriteFunc is Write for a caller that streams its content into the temporary file.
func WriteFunc(path string, mode os.FileMode, fill func(*os.File) error) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if err = fill(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir makes a rename in dir durable. Some filesystems cannot sync a folder; that is not an error here.
func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the folder of a file the caller is already writing
	if err != nil {
		return nil
	}
	defer d.Close()
	_ = d.Sync()
	return nil
}
