package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/modules"
)

func serveFile(t *testing.T, path string) (*httptest.Server, *string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &body
}

func tool(t *testing.T, srv *httptest.Server, dir, stdin string) (*moduleTool, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &moduleTool{dir: dir, client: srv.Client(), in: strings.NewReader(stdin), out: out}, out
}

func TestModuleInstall_ApproveUpdateAndTamper(t *testing.T) {
	srv, body := serveFile(t, "../../docs/examples/mygame/module.yaml")
	dir := t.TempDir()

	// Not approved: nothing lands on disk.
	tl, out := tool(t, srv, dir, "no\n")
	if code := tl.run([]string{"install", srv.URL + "/m.yaml"}); code != 1 {
		t.Fatalf("declined install exit %d:\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "mygame")); err == nil {
		t.Fatal("a declined install wrote files")
	}

	// A wrong pinned hash is refused even with --yes.
	tl, out = tool(t, srv, dir, "")
	if code := tl.run([]string{"install", srv.URL + "/m.yaml", "--sha256", strings.Repeat("0", 64), "--yes"}); code != 1 || !strings.Contains(out.String(), "hash mismatch") {
		t.Fatalf("bad hash: exit %d\n%s", code, out)
	}

	// Approved by typing the id; the review lists the image.
	tl, out = tool(t, srv, dir, "mygame\n")
	if code := tl.run([]string{"install", srv.URL + "/m.yaml"}); code != 0 {
		t.Fatalf("install exit %d:\n%s", code, out)
	}
	if !strings.Contains(out.String(), "runs the container image") {
		t.Errorf("no review shown:\n%s", out)
	}

	// Loading it works while it matches the lock ...
	if err := modules.NewSet().LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	s := modules.NewSet()
	if err := s.LoadDir(dir); err != nil || len(s.IDs()) != 1 {
		t.Fatalf("locked module did not load: %v %v", err, s.IDs())
	}

	// ... and an edit on disk keeps it out.
	p := filepath.Join(dir, "mygame", "module.yaml")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, append(b, []byte("# tampered\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	s = modules.NewSet()
	if err := s.LoadDir(dir); err != nil || len(s.IDs()) != 0 {
		t.Fatalf("a changed module still loaded: %v %v", err, s.IDs())
	}
	tl, out = tool(t, srv, dir, "")
	tl.run([]string{"list"})
	if !strings.Contains(out.String(), "CHANGED") {
		t.Errorf("list did not flag the change:\n%s", out)
	}

	// The source is unchanged from what was approved, so update restores it.
	tl, out = tool(t, srv, dir, "")
	if code := tl.run([]string{"update", "mygame"}); code != 0 {
		t.Fatalf("restore exit %d:\n%s", code, out)
	}
	s = modules.NewSet()
	if err := s.LoadDir(dir); err != nil || len(s.IDs()) != 1 {
		t.Fatalf("restored module did not load: %v", s.IDs())
	}

	// The source changes upstream: update shows what is new and needs approval.
	*body = strings.Replace(*body, "image:", "secopts: [\"seccomp=unconfined\"]\n  image:", 1)
	tl, out = tool(t, srv, dir, "nope\n")
	if code := tl.run([]string{"update", "mygame"}); code != 1 {
		t.Fatalf("declined update exit %d:\n%s", code, out)
	}
	if !strings.Contains(out.String(), "seccomp=unconfined") {
		t.Errorf("update did not show the new capability:\n%s", out)
	}
	tl, out = tool(t, srv, dir, "mygame\n")
	if code := tl.run([]string{"update", "mygame"}); code != 0 {
		t.Fatalf("approved update exit %d:\n%s", code, out)
	}

	// Remove.
	tl, out = tool(t, srv, dir, "")
	if code := tl.run([]string{"remove", "mygame"}); code != 0 {
		t.Fatalf("remove exit %d:\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "mygame")); err == nil {
		t.Error("remove left the folder")
	}
}

func TestModuleInstall_Refusals(t *testing.T) {
	srv, _ := serveFile(t, "../../docs/examples/mygame/module.yaml")
	dir := t.TempDir()
	tl, out := tool(t, srv, dir, "")
	if code := tl.run([]string{"install", "http://example.com/m.yaml", "--yes"}); code != 1 || !strings.Contains(out.String(), "https") {
		t.Errorf("plain http accepted: %d\n%s", code, out)
	}
	// A hand-placed module is not clobbered.
	if err := os.MkdirAll(filepath.Join(dir, "mygame"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mygame", "module.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tl, out = tool(t, srv, dir, "")
	if code := tl.run([]string{"install", srv.URL + "/m.yaml", "--yes"}); code != 1 || !strings.Contains(out.String(), "not installed by crowsnest") {
		t.Errorf("clobbered a hand-placed module: %d\n%s", code, out)
	}
	// No modules_dir.
	tl, out = tool(t, srv, "", "")
	if code := tl.run([]string{"list"}); code != 1 {
		t.Errorf("empty modules_dir: %d", code)
	}
}

func TestModuleInstall_BundledIDRefused(t *testing.T) {
	body := []byte("api_version: 1\nid: valheim\nname: V\nruntime:\n  image: x/y\n")
	if _, err := modules.Install(t.TempDir(), "https://x/y", body, "", false); err == nil {
		t.Error("a bundled id was installable")
	}
}
