package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, msgs ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		l.Record(m)
	}
	l.Close()
	return p
}

func TestChainVerifiesAndContinuesAcrossOpens(t *testing.T) {
	p := write(t, "a", "b", "c")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	l.Record("d")
	l.Close()
	n, last, err := Verify(p)
	if err != nil || n != 4 || len(last) != 64 {
		t.Fatalf("n=%d last=%q err=%v", n, last, err)
	}
}

func TestEditRemoveAndReorderAreDetected(t *testing.T) {
	p := write(t, "alice started palworld", "bob stopped palworld", "carol changed settings", "dave signed in")
	raw, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	cases := map[string][]string{
		"edit":    {lines[0], strings.Replace(lines[1], "bob", "eve", 1), lines[2], lines[3]},
		"remove":  {lines[0], lines[2], lines[3]},
		"reorder": {lines[0], lines[2], lines[1], lines[3]},
		"junk":    {lines[0], "not json"},
	}
	for name, ls := range cases {
		bad := filepath.Join(t.TempDir(), "x.jsonl")
		os.WriteFile(bad, []byte(strings.Join(ls, "\n")+"\n"), 0o600)
		if _, _, err := Verify(bad); err == nil {
			t.Errorf("%s: not detected", name)
		}
		if _, err := Open(bad); err == nil {
			t.Errorf("%s: Open extended a broken chain", name)
		}
	}
}

func TestNilAndMissing(t *testing.T) {
	var l *Log
	l.Record("x") // must not panic
	if _, _, err := Verify(filepath.Join(t.TempDir(), "none")); !os.IsNotExist(err) {
		t.Errorf("err = %v, want not-exist", err)
	}
	if n, last, err := Verify(write(t)); n != 0 || last != "" || err != nil {
		t.Errorf("empty file: %d %q %v", n, last, err)
	}
}
