// Package vault encrypts the secrets CrowsNest keeps on disk (OAuth client
// secrets, game passwords, TOTP seeds, the session-signing key) with
// AES-256-GCM. A sealed value reads "enc:v1:<base64>"; a value without that
// prefix is legacy plaintext, which Unseal returns unchanged so old files can
// be read once and rewritten sealed.
//
// The key comes from the CROWSNEST_MASTER_KEY environment variable when set
// (supply it from outside the data volume: a Docker secret, the host's .env,
// a systemd credential), otherwise from a key file that is created on first
// use. A key file next to the data only protects against a copy of part of the
// volume (one backed-up file, a misdirected share), not a copy of all of it,
// so Source reports which one is in use and the server warns on "file".
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// EnvKey names the environment variable that holds the master key.
const EnvKey = "CROWSNEST_MASTER_KEY"

// MinEnvKeyLen is the shortest master key accepted from the environment.
const MinEnvKeyLen = 24

const prefix = "enc:v1:"

// Source says where the master key came from.
const (
	SourceEnv  = "environment"
	SourceFile = "file"
)

// Vault seals and unseals values. The zero value and nil do nothing: they
// pass values through, which tests use; the server always builds a real one.
type Vault struct {
	aead   cipher.AEAD
	Source string
}

// New builds a vault from envValue (the master key from the environment, may
// be empty) or, failing that, the key file at keyFile, created if missing.
func New(envValue, keyFile string) (*Vault, error) {
	var material []byte
	source := SourceEnv
	if envValue = strings.TrimSpace(envValue); envValue != "" {
		if len(envValue) < MinEnvKeyLen {
			return nil, fmt.Errorf("vault: %s must be at least %d characters (try `openssl rand -base64 32`)", EnvKey, MinEnvKeyLen)
		}
		material = []byte(envValue)
	} else {
		source = SourceFile
		b, err := os.ReadFile(keyFile) // #nosec G304 -- keyFile derives from the operator's config.yaml
		switch {
		case err == nil:
			if len(b) < 32 {
				return nil, fmt.Errorf("vault: key file %s is too short", keyFile)
			}
			material = b
		case os.IsNotExist(err):
			material = make([]byte, 32)
			if _, err := rand.Read(material); err != nil {
				return nil, err
			}
			if err := os.WriteFile(keyFile, material, 0o600); err != nil {
				return nil, fmt.Errorf("vault: write key file %s: %w", keyFile, err)
			}
		default:
			return nil, fmt.Errorf("vault: read key file %s: %w", keyFile, err)
		}
	}
	sum := sha256.Sum256(append([]byte("crowsnest vault key v1:"), material...))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead, Source: source}, nil
}

// IsSealed reports whether s is a sealed value.
func IsSealed(s string) bool { return strings.HasPrefix(s, prefix) }

// Seal encrypts plain, binding it to purpose (for example
// "managed:minecraft:RCON_PASSWORD"), so a sealed value copied into another
// field fails to open. An empty value stays empty.
func (v *Vault) Seal(purpose, plain string) (string, error) {
	if v == nil || v.aead == nil || plain == "" {
		return plain, nil
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return prefix + base64.StdEncoding.EncodeToString(v.aead.Seal(nonce, nonce, []byte(plain), []byte(purpose))), nil
}

// Unseal reverses Seal. A value that is not sealed is returned as it is, with
// legacy true, so the caller can rewrite it sealed.
func (v *Vault) Unseal(purpose, s string) (plain string, legacy bool, err error) {
	if !IsSealed(s) {
		return s, s != "", nil
	}
	if v == nil || v.aead == nil {
		return "", false, errors.New("vault: a sealed value but no key")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil || len(raw) < v.aead.NonceSize() {
		return "", false, errors.New("vault: malformed sealed value")
	}
	n := v.aead.NonceSize()
	out, err := v.aead.Open(nil, raw[:n], raw[n:], []byte(purpose))
	if err != nil {
		return "", false, errors.New("vault: cannot decrypt (wrong master key, or the value was moved)")
	}
	return string(out), false, nil
}
