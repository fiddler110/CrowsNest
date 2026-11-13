package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReplacesAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := Write(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(p, []byte("two"), 0o640); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	info, _ := os.Stat(p)
	if string(b) != "two" || info.Mode().Perm() != 0o640 {
		t.Fatalf("content %q mode %v", b, info.Mode())
	}
	if e, _ := os.ReadDir(dir); len(e) != 1 {
		t.Fatalf("leftover files: %v", e)
	}
}

func TestFailedFillKeepsTheOldFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	_ = Write(p, []byte("keep"), 0o600)
	boom := errors.New("boom")
	if err := WriteFunc(p, 0o600, func(*os.File) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "keep" {
		t.Fatalf("file = %q", b)
	}
	if e, _ := os.ReadDir(dir); len(e) != 1 {
		t.Fatalf("temp file left behind: %v", e)
	}
}

func TestMissingFolderFails(t *testing.T) {
	if err := Write(filepath.Join(t.TempDir(), "nope", "f"), []byte("x"), 0o600); err == nil {
		t.Fatal("wrote into a missing folder")
	}
}
