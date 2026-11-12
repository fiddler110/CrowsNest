package vault

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSealUnseal(t *testing.T) {
	dir := t.TempDir()
	v, err := New("", filepath.Join(dir, "k"))
	if err != nil || v.Source != SourceFile {
		t.Fatalf("New = %v, %v", v, err)
	}
	s, err := v.Seal("a", "hunter2")
	if err != nil || !IsSealed(s) || strings.Contains(s, "hunter2") {
		t.Fatalf("Seal = %q, %v", s, err)
	}
	if got, legacy, err := v.Unseal("a", s); err != nil || legacy || got != "hunter2" {
		t.Fatalf("Unseal = %q %v %v", got, legacy, err)
	}
	if _, _, err := v.Unseal("b", s); err == nil {
		t.Error("opened under another purpose")
	}
	if got, legacy, _ := v.Unseal("a", "plain"); got != "plain" || !legacy {
		t.Errorf("legacy plaintext = %q %v", got, legacy)
	}
	// Same key file reopens; an env key is a different key.
	v2, _ := New("", filepath.Join(dir, "k"))
	if got, _, err := v2.Unseal("a", s); err != nil || got != "hunter2" {
		t.Errorf("reopen: %q %v", got, err)
	}
	v3, err := New("a-long-enough-master-key-value", "")
	if err != nil || v3.Source != SourceEnv {
		t.Fatal(err)
	}
	if _, _, err := v3.Unseal("a", s); err == nil {
		t.Error("opened with a different key")
	}
	if _, err := New("short", ""); err == nil {
		t.Error("accepted a short env key")
	}
	if e, _ := (*Vault)(nil).Seal("a", "x"); e != "x" {
		t.Error("nil vault should pass through")
	}
}
