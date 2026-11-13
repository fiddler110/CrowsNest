package vault

import (
	"crypto/sha256"
	"encoding/base64"
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

// sealV1 makes a value the way versions before v2 did.
func sealV1(t *testing.T, material, purpose, plain string) string {
	t.Helper()
	sum := sha256.Sum256(append([]byte("crowsnest vault key v1:"), material...))
	aead, err := newGCM(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	return prefixV1 + base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plain), []byte(purpose)))
}

func TestV1ValuesStillOpenAndNewOnesAreV2(t *testing.T) {
	const pass = "a-long-enough-master-key-value"
	v, err := New(pass, "")
	if err != nil {
		t.Fatal(err)
	}
	old := sealV1(t, pass, "p", "secret")
	got, legacy, err := v.Unseal("p", old)
	if err != nil || got != "secret" || !legacy {
		t.Fatalf("v1 value = %q legacy=%v err=%v", got, legacy, err)
	}
	s, _ := v.Seal("p", "secret")
	if !strings.HasPrefix(s, "enc:v2:") {
		t.Fatalf("new value = %q", s)
	}
	if got, legacy, err := v.Unseal("p", s); err != nil || got != "secret" || legacy {
		t.Fatalf("v2 value = %q legacy=%v err=%v", got, legacy, err)
	}
	// The v2 key is not the v1 key: a v2 body relabelled v1 does not open.
	if _, _, err := v.Unseal("p", "enc:v1:"+strings.TrimPrefix(s, "enc:v2:")); err == nil {
		t.Error("a v2 value opened as v1")
	}
}

func TestResealToANewKeyIsResumable(t *testing.T) {
	oldV, _ := New("old-master-key-long-enough-xxxx", "")
	newV, _ := New("new-master-key-long-enough-xxxx", "")
	s, _ := oldV.Seal("p", "secret")
	moved, changed, err := oldV.Reseal(newV, "p", s)
	if err != nil || !changed {
		t.Fatalf("Reseal = %v %v", changed, err)
	}
	if got, _, err := newV.Unseal("p", moved); err != nil || got != "secret" {
		t.Fatalf("new key: %q %v", got, err)
	}
	if _, _, err := oldV.Unseal("p", moved); err == nil {
		t.Error("old key still opens the moved value")
	}
	// Running it again over an already moved value changes nothing and does not fail.
	again, changed, err := oldV.Reseal(newV, "p", moved)
	if err != nil || changed || again != moved {
		t.Fatalf("second Reseal = %q %v %v", again, changed, err)
	}
	// A value neither key opens is an error.
	other, _ := New("third-master-key-long-enough-xxx", "")
	x, _ := other.Seal("p", "z")
	if _, _, err := oldV.Reseal(newV, "p", x); err == nil {
		t.Error("resealed a value neither key opens")
	}
	// Same key, v1 -> v2.
	v1 := sealV1(t, "old-master-key-long-enough-xxxx", "p", "secret")
	up, changed, err := oldV.Reseal(oldV, "p", v1)
	if err != nil || !changed || !strings.HasPrefix(up, "enc:v2:") {
		t.Fatalf("v1 upgrade = %q %v %v", up, changed, err)
	}
}
