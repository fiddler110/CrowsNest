package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestModuleCheck_BundledAndExampleWithLog(t *testing.T) {
	for _, c := range []struct{ dir, log, want string }{
		{"../../internal/modules/bundled/minecraft", "../../internal/modules/testdata/minecraft_session.log", "peak players 2"},
		{"../../docs/examples/mygame", "../../docs/examples/mygame/sample.log", "peak players 2"},
	} {
		var out strings.Builder
		if code := runModuleCheck([]string{c.dir, "--log", c.log}, &out); code != 0 {
			t.Fatalf("%s: exit %d:\n%s", c.dir, code, out.String())
		}
		for _, want := range []string{"is a valid module", "READY", c.want} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%s: output lacks %q:\n%s", c.dir, want, out.String())
			}
		}
		if strings.Contains(out.String(), "WARN") {
			t.Errorf("%s should check clean:\n%s", c.dir, out.String())
		}
	}
}

func TestModuleCheck_RejectsABadManifestAndWarnsOnAMarkerThatNeverMatches(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mygame")
	os.MkdirAll(dir, 0o755)
	var out strings.Builder
	os.WriteFile(filepath.Join(dir, "module.yaml"), []byte("api_version: 1\nid: mygame\nname: G\nrunetime: {}\n"), 0o644)
	if code := runModuleCheck([]string{dir}, &out); code != 1 || !strings.Contains(out.String(), "FAIL") {
		t.Fatalf("a typo in a key must fail: exit %d\n%s", code, out.String())
	}

	out.Reset()
	os.WriteFile(filepath.Join(dir, "module.yaml"), []byte("api_version: 1\nid: mygame\nname: G\nstatus: {ready_log: 'never printed'}\nplayers: {type: log_markers, join: 'a (\\S+)', leave: 'b (\\S+)'}\n"), 0o644)
	logf := filepath.Join(dir, "x.log")
	os.WriteFile(logf, []byte("hello\nworld\n"), 0o644)
	if code := runModuleCheck([]string{dir, "--log", logf}, &out); code != 0 || !strings.Contains(out.String(), "ready marker never matched") {
		t.Fatalf("exit %d, want a warning about the ready marker:\n%s", code, out.String())
	}
}
