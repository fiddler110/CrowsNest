package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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
