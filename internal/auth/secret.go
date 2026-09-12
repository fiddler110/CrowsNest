package auth

import (
	"crypto/rand"
	"fmt"
	"os"
)

const sessionSecretSize = 32

// LoadOrCreateSecret reads the session-signing secret from path, generating
// and persisting a new random one on first run if the file doesn't exist
// yet. Rotating (deleting) this file invalidates every existing session.
func LoadOrCreateSecret(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
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
