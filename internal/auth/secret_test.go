package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/fiddler110/crowsnest/internal/vault"
)

func TestLoadOrCreateSecret_GeneratesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".session_secret")

	first, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatalf("LoadOrCreateSecret() error = %v", err)
	}
	if len(first) != sessionSecretSize {
		t.Fatalf("len(secret) = %d, want %d", len(first), sessionSecretSize)
	}

	second, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatalf("LoadOrCreateSecret() (second call) error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("LoadOrCreateSecret() returned a different secret on the second call — should persist")
	}
}

func TestLoadOrCreateSecret_TooShort(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".session_secret")
	os.WriteFile(path, []byte("too short"), 0o600)

	if _, err := LoadOrCreateSecret(path); err == nil {
		t.Fatal("LoadOrCreateSecret() error = nil, want error for an undersized existing secret")
	}
}

func TestLoadOrCreateSealedSecret(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.New("", filepath.Join(dir, "k"))
	path := filepath.Join(dir, "session")
	a, err := LoadOrCreateSealedSecret(path, v)
	if err != nil || len(a) != 32 {
		t.Fatalf("create: %v %d", err, len(a))
	}
	raw, _ := os.ReadFile(path)
	if !vault.IsSealed(string(raw)) {
		t.Fatal("secret is not stored sealed")
	}
	b, err := LoadOrCreateSealedSecret(path, v)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("reload differs: %v", err)
	}
	// A legacy raw file keeps its value and is rewritten sealed.
	legacy := filepath.Join(dir, "legacy")
	os.WriteFile(legacy, a, 0o600)
	c, err := LoadOrCreateSealedSecret(legacy, v)
	if err != nil || !bytes.Equal(a, c) {
		t.Fatalf("legacy: %v", err)
	}
	if raw, _ := os.ReadFile(legacy); !vault.IsSealed(string(raw)) {
		t.Fatal("legacy secret was not rewritten sealed")
	}
}
