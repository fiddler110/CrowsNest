package gamefiles

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	ok, err := Normalize([]Spec{{ID: "props", Path: "/data/server.properties"}})
	if err != nil {
		t.Fatal(err)
	}
	if ok[0].MaxBytes != DefaultMaxBytes || ok[0].Restart != "required" || ok[0].Label != "props" {
		t.Fatalf("defaults not applied: %+v", ok[0])
	}
	for name, sp := range map[string]Spec{
		"relative":   {ID: "a", Path: "data/x"},
		"dotdot":     {ID: "a", Path: "/data/../etc/passwd"},
		"glob":       {ID: "a", Path: "/data/*.cfg"},
		"quote":      {ID: "a", Path: "/data/x'y"},
		"proc":       {ID: "a", Path: "/proc/self/environ"},
		"dir":        {ID: "a", Path: "/data/"},
		"bad id":     {ID: "A b", Path: "/data/x"},
		"huge":       {ID: "a", Path: "/data/x", MaxBytes: AbsoluteMax + 1},
		"bad regexp": {ID: "a", Path: "/data/x", Redact: []string{"("}},
		"no group":   {ID: "a", Path: "/data/x", Redact: []string{"password="}},
	} {
		if _, err := Normalize([]Spec{sp}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Normalize([]Spec{{ID: "a", Path: "/x"}, {ID: "a", Path: "/y"}}); err == nil {
		t.Error("duplicate id accepted")
	}
}

func TestHideAndRestore(t *testing.T) {
	sp := Spec{ID: "p", Path: "/x", Redact: []string{`^\s*rcon\.password=(.*)$`}}
	cur := "motd=hi\nrcon.password=hunter2\nport=25565"
	shown := sp.Hide(cur)
	if strings.Contains(shown, "hunter2") || !strings.Contains(shown, "rcon.password="+Mask) {
		t.Fatalf("not hidden: %q", shown)
	}
	// An edit elsewhere keeps the secret.
	got, err := sp.Restore(strings.Replace(shown, "hi", "hello", 1), cur)
	if err != nil || got != "motd=hello\nrcon.password=hunter2\nport=25565" {
		t.Fatalf("restore: %q, %v", got, err)
	}
	// Moving the line keeps it too (matched by text, not position).
	moved := "rcon.password=" + Mask + "\nmotd=hi\nport=25565"
	if got, err = sp.Restore(moved, cur); err != nil || !strings.HasPrefix(got, "rcon.password=hunter2\n") {
		t.Fatalf("moved: %q, %v", got, err)
	}
	// A new real value is written as typed.
	if got, _ = sp.Restore("rcon.password=new", cur); got != "rcon.password=new" {
		t.Fatalf("typed value lost: %q", got)
	}
	// A mask with nothing to put back is refused, never written.
	if _, err = sp.Restore("rcon.password="+Mask, "motd=hi"); !errors.Is(err, ErrHiddenValue) {
		t.Fatalf("want ErrHiddenValue, got %v", err)
	}
	// A mask-looking line that is not a redacted one is left alone.
	if got, err = sp.Restore("motd="+Mask, cur); err != nil || got != "motd="+Mask {
		t.Fatalf("plain line: %q, %v", got, err)
	}
}

func TestArgs(t *testing.T) {
	sp := Spec{ID: "p", Path: "/data/a b.properties", MaxBytes: 100}
	if r := sp.ReadArgs(); r[0] != "sh" || r[2] != readScript || r[4] != "/data/a b.properties" || r[5] != "101" {
		t.Fatalf("read args: %q", r)
	}
	w := sp.WriteArgs()
	if w[0] != "sh" || w[len(w)-1] != sp.Path || w[2] != writeScript {
		t.Fatalf("write args: %q", w)
	}
}

// fakeDocker is a container with one file.
type fakeDocker struct {
	down    bool // the container is stopped
	mu      sync.Mutex
	content string
	writes  int
	failW   bool
}

func (f *fakeDocker) Running(context.Context, string) (bool, error) { return !f.down, nil }

func (f *fakeDocker) ExecTimeout(_ context.Context, _ string, _ time.Duration, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if args[2] != readScript {
		return "", errors.New("unexpected command")
	}
	return f.content, nil
}

func (f *fakeDocker) ExecStdin(_ context.Context, _ string, in io.Reader, _ time.Duration, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if args[2] != writeScript || f.failW {
		return "", errors.New("write failed")
	}
	b, _ := io.ReadAll(in)
	f.content = string(b)
	f.writes++
	return "", nil
}

func TestServiceWrite(t *testing.T) {
	fd := &fakeDocker{content: "a=1\npass=secret\n"}
	svc := &Service{Docker: fd, HistoryDir: t.TempDir()}
	sp, _ := Normalize([]Spec{{ID: "cfg", Path: "/c", MaxBytes: 64, Redact: []string{`^pass=(.*)$`}}})
	s := sp[0]
	ctx := context.Background()

	content, hash, err := svc.Read(ctx, "g", "g", s)
	if err != nil || content != fd.content {
		t.Fatalf("read: %q %v", content, err)
	}
	// Save with the secret masked: only a=1 changes, the secret is kept.
	h2, err := svc.Write(ctx, "g", "g", s, "a=2\npass="+Mask+"\n", hash)
	if err != nil || fd.content != "a=2\npass=secret\n" || h2 == hash {
		t.Fatalf("write: %q %v", fd.content, err)
	}
	// The old version was kept.
	vs, _ := svc.History("g", s)
	if len(vs) != 1 {
		t.Fatalf("history: %v", vs)
	}
	if old, err := svc.Version("g", s, vs[0].ID); err != nil || old != "a=1\npass=secret\n" {
		t.Fatalf("version: %q %v", old, err)
	}
	if _, err := svc.Version("g", s, "../../etc/passwd"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path in version id: %v", err)
	}
	// A stale hash is refused and nothing is written.
	writes := fd.writes
	if _, err = svc.Write(ctx, "g", "g", s, "a=3\n", hash); !errors.Is(err, ErrChanged) || fd.writes != writes {
		t.Fatalf("stale: %v", err)
	}
	// Unchanged content writes nothing.
	if _, err = svc.Write(ctx, "g", "g", s, "a=2\npass="+Mask+"\n", h2); err != nil || fd.writes != writes {
		t.Fatalf("no-op: %v", err)
	}
	// Too large, and not text.
	if _, err = svc.Write(ctx, "g", "g", s, strings.Repeat("x", 65), h2); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("large: %v", err)
	}
	if _, err = svc.Write(ctx, "g", "g", s, "a\x00b", h2); !errors.Is(err, ErrNotText) {
		t.Fatalf("binary: %v", err)
	}
	// A failed write leaves the container as it was (and keeps its history).
	fd.failW = true
	if _, err = svc.Write(ctx, "g", "g", s, "a=9\n", h2); err == nil {
		t.Fatal("failed write reported success")
	}
}

func TestServiceKeepsOnlyRecentVersions(t *testing.T) {
	fd := &fakeDocker{content: "0"}
	svc := &Service{Docker: fd, HistoryDir: t.TempDir()}
	s := Spec{ID: "c", Path: "/c", MaxBytes: 64}
	h := Hash([]byte("0"))
	for i := 1; i <= KeepVersions+3; i++ {
		var err error
		if h, err = svc.Write(context.Background(), "g", "g", s, strings.Repeat("x", i), h); err != nil {
			t.Fatal(err)
		}
	}
	if vs, _ := svc.History("g", s); len(vs) != KeepVersions {
		t.Fatalf("kept %d, want %d", len(vs), KeepVersions)
	}
}

// The two shell scripts run for real here: they are what the container executes.
func TestScriptsOnARealShell(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/a b.conf"
	sp := Spec{ID: "c", Path: path, MaxBytes: 8}
	run := func(stdin string, args []string) (string, error) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.Output()
		return string(out), err
	}
	if out, err := run("", sp.ReadArgs()); err != nil || out != "" { // missing file reads as empty
		t.Fatalf("missing: %q %v", out, err)
	}
	if _, err := run("one\n", sp.WriteArgs()); err != nil { // creates it
		t.Fatal(err)
	}
	if out, _ := run("", sp.ReadArgs()); out != "one\n" {
		t.Fatalf("read back %q", out)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := run("two\n", sp.WriteArgs()); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode lost: %v", fi.Mode())
	}
	if _, err := os.Stat(path + ".crowsnest-tmp"); err == nil {
		t.Fatal("temp file left behind")
	}
	if out, _ := run("", sp.ReadArgs()); out != "two\n" {
		t.Fatalf("after overwrite %q", out)
	}
	// One byte past the limit is returned, so the caller can see it is too long.
	if _, err := run("0123456789", sp.WriteArgs()); err != nil {
		t.Fatal(err)
	}
	if out, _ := run("", sp.ReadArgs()); len(out) != 9 {
		t.Fatalf("limit+1 read gave %d bytes", len(out))
	}
	// A failed write (directory missing) must fail loudly and not touch the original.
	bad := Spec{ID: "c", Path: dir + "/nope/x", MaxBytes: 8}
	if _, err := run("x", bad.WriteArgs()); err == nil {
		t.Fatal("write into a missing folder reported success")
	}
}

// Palworld keeps every setting, secrets included, on one line.
func TestRedactSeveralSecretsOnOneLine(t *testing.T) {
	sp := Spec{ID: "p", Path: "/x", Redact: []string{`ServerPassword="([^"]*)"`, `AdminPassword="([^"]*)"`}}
	cur := `[/Script/Pal.PalGameWorldSettings]` + "\n" + `OptionSettings=(Difficulty=None,ServerPassword="join-pw",AdminPassword="adm-pw",PublicPort=8211)`
	shown := sp.Hide(cur)
	if strings.Contains(shown, "join-pw") || strings.Contains(shown, "adm-pw") || strings.Count(shown, Mask) != 2 {
		t.Fatalf("hidden: %q", shown)
	}
	// Editing another setting on the same line keeps both secrets.
	got, err := sp.Restore(strings.Replace(shown, "PublicPort=8211", "PublicPort=8300", 1), cur)
	if err != nil || got != strings.Replace(cur, "PublicPort=8211", "PublicPort=8300", 1) {
		t.Fatalf("restore: %q %v", got, err)
	}
	// Changing one secret keeps the other.
	got, _ = sp.Restore(strings.Replace(shown, `ServerPassword="`+Mask+`"`, `ServerPassword="new"`, 1), cur)
	if !strings.Contains(got, `ServerPassword="new"`) || !strings.Contains(got, `AdminPassword="adm-pw"`) {
		t.Fatalf("one changed: %q", got)
	}
}

// fakeHelper is the one-shot container: it sees the same file as the running container.
type fakeHelper struct {
	fd  *fakeDocker
	ok  bool
	use int
}

func (h *fakeHelper) CanEditStopped(string, Spec) bool { return h.ok }
func (h *fakeHelper) ReadStopped(context.Context, string, Spec) (string, error) {
	h.use++
	return h.fd.content, nil
}
func (h *fakeHelper) WriteStopped(_ context.Context, _ string, _ Spec, c string) error {
	h.use++
	h.fd.content = c
	return nil
}

func TestStoppedGameUsesTheHelperOnlyWhenItCan(t *testing.T) {
	fd := &fakeDocker{content: "a=1\n", down: true}
	h := &fakeHelper{fd: fd, ok: true}
	svc := &Service{Docker: fd, Helper: h, HistoryDir: t.TempDir()}
	s := Spec{ID: "c", Path: "/c", MaxBytes: 64}
	ctx := context.Background()
	_, hash, err := svc.Read(ctx, "g", "g", s)
	if err != nil || h.use != 1 {
		t.Fatalf("read via helper: %v (uses %d)", err, h.use)
	}
	if _, err := svc.Write(ctx, "g", "g", s, "a=2\n", hash); err != nil || fd.content != "a=2\n" || fd.writes != 0 {
		t.Fatalf("write via helper: %q %v (exec writes %d)", fd.content, err, fd.writes)
	}
	// A file outside the data folders cannot be reached while stopped.
	h.ok = false
	if _, _, err := svc.Read(ctx, "g", "g", s); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("want ErrNotRunning, got %v", err)
	}
	// With no helper at all (a config.yaml game) it is the same.
	svc.Helper = nil
	if _, _, err := svc.Read(ctx, "g", "g", s); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("no helper: %v", err)
	}
	// Running: exec, never the helper.
	fd.down, h.ok, svc.Helper = false, true, h
	before := h.use
	if _, _, err := svc.Read(ctx, "g", "g", s); err != nil || h.use != before {
		t.Fatalf("running game used the helper: %v", err)
	}
}
