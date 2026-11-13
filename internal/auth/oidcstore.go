package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/fiddler110/crowsnest/internal/vault"
)

// OIDCProvider is one OpenID Connect sign-in provider (Authentik, Keycloak,
// Microsoft Entra, Okta, Auth0, GitHub Enterprise via OIDC, ...). Its
// endpoints come from the issuer's discovery document, fetched when the
// provider is saved.
type OIDCProvider struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"-"`
	RedirectURL  string `json:"redirect_url"`
	AuthURL      string `json:"auth_url"`
	TokenURL     string `json:"token_url"`
	JWKSURL      string `json:"jwks_url,omitempty"` // where its ID-token signing keys are published
	Enabled      bool   `json:"enabled"`
}

var oidcIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,23}$`)

// OIDCCallbackPath is where provider id's callback is served.
func OIDCCallbackPath(id string) string { return "/auth/oidc/" + id + "/callback" }

// OIDCStartPath is where provider id's sign-in starts.
func OIDCStartPath(id string) string { return "/auth/oidc/" + id + "/start" }

func httpsOrLocal(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("must be an absolute URL")
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, errors.New("must use https (http is only allowed for localhost)")
	}
	return u, nil
}

// Validate checks p's own fields (not the discovered endpoints).
func (p OIDCProvider) Validate() error {
	if p.ID == GoogleProviderID {
		return errors.New("the id \"google\" is reserved for the built-in Google sign-in")
	}
	if !oidcIDPattern.MatchString(p.ID) {
		return errors.New("the id must be 1-24 lowercase letters, digits or '-'")
	}
	if n := strings.TrimSpace(p.Name); n == "" || len(n) > 40 {
		return errors.New("give the provider a name of up to 40 characters")
	}
	if u, err := httpsOrLocal(p.Issuer); err != nil || u.RawQuery != "" {
		return errors.New("the issuer URL must be an absolute https URL with no query")
	}
	for name, v := range map[string]string{"client ID": p.ClientID, "client secret": p.ClientSecret} {
		if v == "" || len(v) > 512 || strings.ContainsAny(v, " \t\r\n") {
			return fmt.Errorf("the %s must be one word of up to 512 characters, with no spaces", name)
		}
	}
	u, err := httpsOrLocal(p.RedirectURL)
	if err != nil || u.RawQuery != "" || u.Path != OIDCCallbackPath(p.ID) {
		return fmt.Errorf("the redirect URL must be an absolute https URL ending in %s", OIDCCallbackPath(p.ID))
	}
	return nil
}

type oidcFile struct {
	Providers []oidcProviderFile           `json:"providers"`
	Links     map[string]map[string]string `json:"links,omitempty"` // provider id -> subject -> username
}

type oidcProviderFile struct {
	OIDCProvider
	ClientSecretSealed string `json:"client_secret_enc"`
}

// OIDCStore keeps the providers and the account links (which provider
// subject is which user) in a JSON file, client secrets sealed by the vault.
type OIDCStore struct {
	path  string
	vault *vault.Vault

	mu        sync.Mutex
	providers map[string]OIDCProvider
	links     map[string]map[string]string
}

func oidcPurpose(id string) string { return "oidc-client-secret:" + id }

// NewOIDCStore opens path; a missing file means no providers. A provider
// whose secret can't be decrypted (the master key changed) is kept switched
// off with an empty secret and reported in the error, so it can be re-entered.
func NewOIDCStore(path string, v *vault.Vault) (*OIDCStore, error) {
	s := &OIDCStore{path: path, vault: v, providers: map[string]OIDCProvider{}, links: map[string]map[string]string{}}
	raw, err := os.ReadFile(path) // #nosec G304 -- path derives from the operator's config.yaml
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: read %s: %w", path, err)
	}
	var f oidcFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	var bad []string
	for _, pf := range f.Providers {
		p := pf.OIDCProvider
		secret, _, err := v.Unseal(oidcPurpose(p.ID), pf.ClientSecretSealed)
		if err != nil {
			p.Enabled, secret = false, ""
			bad = append(bad, p.ID)
		}
		p.ClientSecret = secret
		s.providers[p.ID] = p
	}
	if f.Links != nil {
		s.links = f.Links
	}
	if len(bad) > 0 {
		return s, fmt.Errorf("auth: %s: the client secret of %s can't be decrypted (master key changed?); enter it again in Settings", path, strings.Join(bad, ", "))
	}
	return s, nil
}

func (s *OIDCStore) saveLocked() error {
	f := oidcFile{Links: s.links}
	ids := make([]string, 0, len(s.providers))
	for id := range s.providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := s.providers[id]
		sealed, err := s.vault.Seal(oidcPurpose(id), p.ClientSecret)
		if err != nil {
			return err
		}
		f.Providers = append(f.Providers, oidcProviderFile{OIDCProvider: p, ClientSecretSealed: sealed})
	}
	out, _ := json.MarshalIndent(f, "", "  ")
	return writeFileAtomic(s.path, append(out, '\n'))
}

// List returns every provider, by id.
func (s *OIDCStore) List() []OIDCProvider {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]OIDCProvider, 0, len(s.providers))
	for _, p := range s.providers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns provider id.
func (s *OIDCStore) Get(id string) (OIDCProvider, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.providers[id]
	return p, ok
}

// AnyEnabled reports whether some provider is switched on.
func (s *OIDCStore) AnyEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.providers {
		if p.Enabled {
			return true
		}
	}
	return false
}

// Put adds or replaces a provider.
func (s *OIDCStore) Put(p OIDCProvider) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.AuthURL == "" || p.TokenURL == "" {
		return errors.New("the provider's endpoints have not been discovered")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.providers[p.ID]
	s.providers[p.ID] = p
	if had && prev.Issuer != p.Issuer {
		delete(s.links, p.ID) // another identity provider: its subjects mean nothing here
	}
	if err := s.saveLocked(); err != nil {
		if had {
			s.providers[p.ID] = prev
		} else {
			delete(s.providers, p.ID)
		}
		return err
	}
	return nil
}

// Delete removes provider id and the links made through it.
func (s *OIDCStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.providers[id]; !ok {
		return errors.New("no such provider")
	}
	prevLinks := s.links[id]
	prev := s.providers[id]
	delete(s.providers, id)
	delete(s.links, id)
	if err := s.saveLocked(); err != nil {
		s.providers[id], s.links[id] = prev, prevLinks
		return err
	}
	return nil
}

// LinkedUser is the user subject sub of provider id is bound to.
func (s *OIDCStore) LinkedUser(id, sub string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.links[id][sub]
	return u, ok
}

// Link binds subject sub of provider id to username, refusing if the user is
// already bound to a different subject there.
func (s *OIDCStore) Link(id, sub, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for other, u := range s.links[id] {
		if u == username && other != sub {
			return errors.New("that user is already linked to a different account at this provider")
		}
	}
	if s.links[id] == nil {
		s.links[id] = map[string]string{}
	}
	s.links[id][sub] = username
	return s.saveLocked()
}

// UnlinkProvider forgets username's link at one provider (their Google email was changed or removed).
func (s *OIDCStore) UnlinkProvider(id, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for sub, u := range s.links[id] {
		if u == username {
			delete(s.links[id], sub)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.saveLocked()
}

// Unlink forgets every link of username (their SSO email was changed or
// removed, or they were deleted).
func (s *OIDCStore) Unlink(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, m := range s.links {
		for sub, u := range m {
			if u == username {
				delete(m, sub)
				changed = true
			}
		}
	}
	if !changed {
		return nil
	}
	return s.saveLocked()
}
