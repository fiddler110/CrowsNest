package modules

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// A module can be published with a detached ed25519 signature, so the dashboard can install it without anyone
// reading a hash off a web page. The operator lists the public keys they trust in config.yaml (managed.trusted_keys);
// the dashboard cannot change that list. The signature is over signPrefix plus the manifest's exact bytes, so a
// signature made for a module can never be mistaken for one over some other file, and it is served next to the
// manifest as <url>.sig (base64, one line).

// SigSuffix is appended to a manifest's URL to find its signature.
const SigSuffix = ".sig"

const signPrefix = "crowsnest-module-v1\n"

// TrustedKey is one publisher key the operator trusts.
type TrustedKey struct {
	Name string            `yaml:"name"`
	Key  string            `yaml:"public_key"` // base64 of the 32-byte ed25519 public key
	pub  ed25519.PublicKey `yaml:"-"`
}

var keyNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,63}$`)

// ParseTrustedKeys checks the keys of a config and decodes them. Names must be unique.
func ParseTrustedKeys(in []TrustedKey) ([]TrustedKey, error) {
	seen := map[string]bool{}
	out := make([]TrustedKey, 0, len(in))
	for i, k := range in {
		if !keyNameRe.MatchString(k.Name) {
			return nil, fmt.Errorf("trusted_keys[%d]: name %q must be 1-64 letters, digits, spaces or . _ @ -", i, k.Name)
		}
		if seen[k.Name] {
			return nil, fmt.Errorf("trusted_keys: name %q is listed twice", k.Name)
		}
		seen[k.Name] = true
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k.Key))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trusted_keys[%d] (%s): public_key must be the base64 of a 32-byte ed25519 key", i, k.Name)
		}
		k.pub = ed25519.PublicKey(raw)
		out = append(out, k)
	}
	return out, nil
}

// ErrNotSigned means no signature was found, or none matches a trusted key.
var ErrNotSigned = errors.New("no trusted key signed this module")

// VerifySignature says which trusted key signed body. sig is the base64 text of the .sig file.
func VerifySignature(keys []TrustedKey, body, sig []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return "", fmt.Errorf("%w: the signature file is not a base64 ed25519 signature", ErrNotSigned)
	}
	msg := append([]byte(signPrefix), body...)
	for _, k := range keys {
		if len(k.pub) == ed25519.PublicKeySize && ed25519.Verify(k.pub, msg, raw) {
			return k.Name, nil
		}
	}
	return "", ErrNotSigned
}

// GenerateKey makes a publisher key pair: the base64 seed to keep secret, and the base64 public key to give out.
func GenerateKey() (seed, public string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Seed()), base64.StdEncoding.EncodeToString(pub), nil
}

// Sign signs body with a seed from GenerateKey and returns the text of the .sig file.
func Sign(seed string, body []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seed))
	if err != nil || len(raw) != ed25519.SeedSize {
		return nil, errors.New("the key file is not a base64 ed25519 seed")
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(raw), append([]byte(signPrefix), body...))
	return []byte(base64.StdEncoding.EncodeToString(sig) + "\n"), nil
}
