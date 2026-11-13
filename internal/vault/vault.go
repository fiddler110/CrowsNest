// Package vault encrypts the secrets CrowsNest keeps on disk (OAuth client
// secrets, game passwords, TOTP seeds, the session-signing key) with
// AES-256-GCM. A sealed value reads "enc:v2:<base64>" (new values) or
// "enc:v1:<base64>" (written by older versions, still readable); a value
// without either prefix is legacy plaintext, which Unseal returns unchanged so
// old files can be read once and rewritten sealed. v2 derives the AES key from
// the master key with Argon2id (a typed passphrase) or HKDF (a random key
// file); v1 was one plain SHA-256. `crowsnest rekey` moves every file to v2 or
// to a new master key.
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
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// EnvKey names the environment variable that holds the master key.
const EnvKey = "CROWSNEST_MASTER_KEY"

// MinEnvKeyLen is the shortest master key accepted from the environment.
const MinEnvKeyLen = 24

const (
	prefixV1 = "enc:v1:"
	prefixV2 = "enc:v2:"
)

// Source says where the master key came from.
const (
	SourceEnv  = "environment"
	SourceFile = "file"
)

// Vault seals and unseals values. The zero value and nil do nothing: they
// pass values through, which tests use; the server always builds a real one.
type Vault struct {
	aead   cipher.AEAD // v2: what new values are sealed with
	legacy cipher.AEAD // v1: only to open values an older version wrote
	Source string
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// deriveV2 turns the master key into the v2 AES key. A passphrase is low-entropy, so it goes through Argon2id (one
// run at start-up, about a tenth of a second); a key file is 32 random bytes, which HKDF only needs to separate
// from other uses.
func deriveV2(material []byte, passphrase bool) ([]byte, error) {
	if passphrase {
		return argon2.IDKey(material, []byte("crowsnest vault v2 salt"), 3, 64*1024, 1, 32), nil
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, material, nil, []byte("crowsnest vault v2 key")), key); err != nil {
		return nil, err
	}
	return key, nil
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
	legacy, err := newGCM(sum[:])
	if err != nil {
		return nil, err
	}
	key, err := deriveV2(material, source == SourceEnv)
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead, legacy: legacy, Source: source}, nil
}

// IsSealed reports whether s is a sealed value.
func IsSealed(s string) bool { return strings.HasPrefix(s, prefixV1) || strings.HasPrefix(s, prefixV2) }

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
	return prefixV2 + base64.StdEncoding.EncodeToString(v.aead.Seal(nonce, nonce, []byte(plain), []byte(purpose))), nil
}

// Unseal reverses Seal. A value that is not sealed with the current scheme comes back with legacy true so the
// caller can rewrite it: plain text from an early version, or an "enc:v1:" value.
func (v *Vault) Unseal(purpose, s string) (plain string, legacy bool, err error) {
	if !IsSealed(s) {
		return s, s != "", nil
	}
	if v == nil || v.aead == nil {
		return "", false, errors.New("vault: a sealed value but no key")
	}
	aead, body := v.aead, strings.TrimPrefix(s, prefixV2)
	if strings.HasPrefix(s, prefixV1) {
		aead, body, legacy = v.legacy, strings.TrimPrefix(s, prefixV1), true
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil || len(raw) < aead.NonceSize() {
		return "", false, errors.New("vault: malformed sealed value")
	}
	n := aead.NonceSize()
	out, err := aead.Open(nil, raw[:n], raw[n:], []byte(purpose))
	if err != nil {
		return "", false, errors.New("vault: cannot decrypt (wrong master key, or the value was moved)")
	}
	return string(out), legacy, nil
}

// Reseal reads s with v and seals it again with to (a vault made from another master key, or the same one to move
// a v1 value to v2). A value that v cannot open but to can is already done and comes back unchanged, so an
// interrupted rekey can be run again. changed says the returned text differs from s.
func (v *Vault) Reseal(to *Vault, purpose, s string) (out string, changed bool, err error) {
	if s == "" {
		return s, false, nil
	}
	plain, legacy, err := v.Unseal(purpose, s)
	if err == nil && !legacy && IsSealed(s) {
		if _, _, err2 := to.Unseal(purpose, s); err2 == nil {
			return s, false, nil // v and to are the same key and the value is already current
		}
	}
	if err != nil {
		if _, legacy, err2 := to.Unseal(purpose, s); err2 == nil && !legacy && IsSealed(s) {
			return s, false, nil
		}
		return "", false, err
	}
	out, err = to.Seal(purpose, plain)
	return out, out != s, err
}
