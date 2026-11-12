package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/fiddler110/crowsnest/internal/vault"
)

const sessionSecretSize = 32

// LoadOrCreateSecret reads the session-signing secret from path, generating
// and persisting a new random one on first run if the file doesn't exist
// yet. Rotating (deleting) this file invalidates every existing session.
func LoadOrCreateSecret(path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- session_secret_file path comes from the operator's config.yaml
	if err == nil {
		if len(data) < sessionSecretSize {
			return nil, fmt.Errorf("auth: session secret file %s is too short (want >= %d bytes)", path, sessionSecretSize)
		}
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("auth: read session secret %s: %w", path, err)
	}

	secret := make([]byte, sessionSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("auth: generate session secret: %w", err)
	}
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		return nil, fmt.Errorf("auth: write session secret %s: %w", path, err)
	}
	return secret, nil
}

const sessionSecretPurpose = "session-secret"

// LoadOrCreateSealedSecret is LoadOrCreateSecret with the file encrypted by v:
// it holds "enc:v1:..." text instead of raw bytes. A raw file left by an older
// version is read as it is and rewritten sealed.
func LoadOrCreateSealedSecret(path string, v *vault.Vault) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- session_secret_file path comes from the operator's config.yaml
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("auth: read session secret %s: %w", path, err)
	}
	if err == nil && vault.IsSealed(string(data)) {
		plain, _, err := v.Unseal(sessionSecretPurpose, strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("auth: session secret %s: %w", path, err)
		}
		b, err := base64.StdEncoding.DecodeString(plain)
		if err != nil || len(b) < sessionSecretSize {
			return nil, fmt.Errorf("auth: session secret %s is damaged", path)
		}
		return b, nil
	}
	var secret []byte
	if err == nil {
		if len(data) < sessionSecretSize {
			return nil, fmt.Errorf("auth: session secret file %s is too short (want >= %d bytes)", path, sessionSecretSize)
		}
		secret = data // legacy raw file
	} else {
		secret = make([]byte, sessionSecretSize)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("auth: generate session secret: %w", err)
		}
	}
	sealed, err := v.Seal(sessionSecretPurpose, base64.StdEncoding.EncodeToString(secret))
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, []byte(sealed+"\n")); err != nil {
		return nil, err
	}
	return secret, nil
}
