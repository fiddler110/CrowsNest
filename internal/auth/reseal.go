package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fiddler110/crowsnest/internal/vault"
)

// The Reseal functions re-encrypt one sealed file under another vault (a new master key, or the same key's newer
// scheme) for `crowsnest rekey`. Each returns how many values changed; a missing file is not an error. They are safe
// to run again after an interruption (see vault.Reseal). The panel must be stopped: it holds these files in memory.

func readIfExists(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- a state file path from the operator's config
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return b, err == nil, err
}

// ResealSessionSecret re-seals the session-signing key file.
func ResealSessionSecret(path string, from, to *vault.Vault) (int, error) {
	b, ok, err := readIfExists(path)
	if err != nil || !ok {
		return 0, err
	}
	text := strings.TrimSpace(string(b))
	if !vault.IsSealed(text) {
		return 0, nil // a raw file from an old version: the next start seals it
	}
	out, changed, err := from.Reseal(to, sessionSecretPurpose, text)
	if err != nil || !changed {
		return 0, err
	}
	return 1, writeFileAtomic(path, []byte(out+"\n"))
}

// ResealGoogleConf re-seals the dashboard's Google client secret.
func ResealGoogleConf(path string, from, to *vault.Vault) (int, error) {
	b, ok, err := readIfExists(path)
	if err != nil || !ok {
		return 0, err
	}
	var f googleConfFile
	if err := json.Unmarshal(b, &f); err != nil {
		return 0, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	out, changed, err := from.Reseal(to, googleSecretPurpose, f.ClientSecret)
	if err != nil || !changed {
		return 0, err
	}
	f.ClientSecret = out
	nb, _ := json.MarshalIndent(f, "", "  ")
	return 1, writeFileAtomic(path, append(nb, '\n'))
}

// ResealOIDC re-seals every OIDC provider's client secret.
func ResealOIDC(path string, from, to *vault.Vault) (int, error) {
	b, ok, err := readIfExists(path)
	if err != nil || !ok {
		return 0, err
	}
	var f oidcFile
	if err := json.Unmarshal(b, &f); err != nil {
		return 0, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	n := 0
	for i := range f.Providers {
		out, changed, err := from.Reseal(to, oidcPurpose(f.Providers[i].ID), f.Providers[i].ClientSecretSealed)
		if err != nil {
			return 0, fmt.Errorf("auth: %s, provider %s: %w", path, f.Providers[i].ID, err)
		}
		if changed {
			f.Providers[i].ClientSecretSealed = out
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	nb, _ := json.MarshalIndent(f, "", "  ")
	return n, writeFileAtomic(path, append(nb, '\n'))
}
