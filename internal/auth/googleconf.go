package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fiddler110/crowsnest/internal/vault"
)

// Where a Google setting comes from.
const (
	GoogleSourceDashboard   = "dashboard"
	GoogleSourceEnvironment = "environment"
	GoogleSourceNone        = "none"
)

// GoogleSettings is the OAuth client behind "Sign in with Google".
type GoogleSettings struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// Validate checks the values are usable. A disabled setting may be partial.
func (g GoogleSettings) Validate() error {
	for name, v := range map[string]string{"client ID": g.ClientID, "client secret": g.ClientSecret} {
		if len(v) > 512 || strings.ContainsAny(v, " \t\r\n") {
			return fmt.Errorf("the %s must be one word of up to 512 characters, with no spaces", name)
		}
	}
	if g.RedirectURL != "" {
		u, err := url.Parse(g.RedirectURL)
		if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return errors.New("the redirect URL must be an absolute URL with no query or fragment")
		}
		local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
		if u.Scheme != "https" && !(u.Scheme == "http" && local) {
			return errors.New("the redirect URL must use https (http is only allowed for localhost)")
		}
		if u.Path != GoogleCallbackPath {
			return fmt.Errorf("the redirect URL must end in %s", GoogleCallbackPath)
		}
	}
	if g.Enabled && (g.ClientID == "" || g.ClientSecret == "" || g.RedirectURL == "") {
		return errors.New("to turn Google sign-in on, give the client ID, the client secret and the redirect URL")
	}
	return nil
}

// GoogleConfStore keeps the Google sign-in settings saved from the dashboard
// in a small JSON file. The client secret is encrypted at rest by the vault. Whatever is saved
// here wins over Fallback, the config.yaml and environment settings.
type GoogleConfStore struct {
	// Fallback is used while nothing is saved from the dashboard.
	Fallback GoogleSettings

	path  string
	vault *vault.Vault

	mu    sync.Mutex
	saved *GoogleSettings
}

type googleConfFile struct {
	Enabled      bool   `json:"enabled"`
	ClientID     string `json:"client_id"`
	RedirectURL  string `json:"redirect_url"`
	ClientSecret string `json:"client_secret_enc"`
}

const googleSecretPurpose = "google-client-secret"

// NewGoogleConfStore opens the settings at path. A missing file means nothing
// is saved. When the saved secret can't be decrypted (the master key changed)
// the store is returned with the error and holds nothing saved, so the
// settings can be entered again.
func NewGoogleConfStore(path string, v *vault.Vault, fallback GoogleSettings) (*GoogleConfStore, error) {
	s := &GoogleConfStore{Fallback: fallback, path: path, vault: v}
	raw, err := os.ReadFile(path) // #nosec G304 -- path derives from the operator's config.yaml
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: read %s: %w", path, err)
	}
	var f googleConfFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	secret, _, err := v.Unseal(googleSecretPurpose, f.ClientSecret)
	if err != nil {
		return s, fmt.Errorf("auth: %s: the saved client secret can't be decrypted (%v); enter it again in Settings", path, err)
	}
	s.saved = &GoogleSettings{Enabled: f.Enabled, ClientID: f.ClientID, ClientSecret: secret, RedirectURL: f.RedirectURL}
	return s, nil
}

// Effective is what sign-in should use now, and where it comes from.
func (s *GoogleConfStore) Effective() (GoogleSettings, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saved != nil {
		return *s.saved, GoogleSourceDashboard
	}
	if s.Fallback.ClientID != "" || s.Fallback.RedirectURL != "" {
		return s.Fallback, GoogleSourceEnvironment
	}
	return GoogleSettings{}, GoogleSourceNone
}

// Save validates and stores v, replacing whatever was saved.
func (s *GoogleConfStore) Save(v GoogleSettings) error {
	if err := v.Validate(); err != nil {
		return err
	}
	enc, err := s.vault.Seal(googleSecretPurpose, v.ClientSecret)
	if err != nil {
		return err
	}
	// #nosec G117 -- ClientSecret holds the sealed (encrypted) value
	out, _ := json.MarshalIndent(googleConfFile{Enabled: v.Enabled, ClientID: v.ClientID, RedirectURL: v.RedirectURL, ClientSecret: enc}, "", "  ")
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeFileAtomic(s.path, append(out, '\n')); err != nil {
		return err
	}
	s.saved = &v
	return nil
}

// Clear forgets what was saved, so the config.yaml and environment settings
// (if any) apply again.
func (s *GoogleConfStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	s.saved = nil
	return nil
}

// Apply points g at the effective settings.
func (s *GoogleConfStore) Apply(g *GoogleLogin) {
	v, _ := s.Effective()
	g.Reconfigure(v.ClientID, v.ClientSecret, v.RedirectURL, v.Enabled)
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".auth-*.tmp")
	if err != nil {
		return fmt.Errorf("auth: write %s: %w", path, err)
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr, os.Chmod(tmp.Name(), 0o600)); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("auth: write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("auth: write %s: %w", path, err)
	}
	return nil
}
