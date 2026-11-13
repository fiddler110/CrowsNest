package modules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// A catalogue is a list of modules somebody publishes in one place, so an admin can pick one instead of pasting
// an address. It is only a list of pointers: it grants nothing and is not trusted. Whatever an entry points at
// still goes through the same signature check, preview and password as a hand-typed address.

// MaxCatalogueBytes caps a downloaded catalogue.
const MaxCatalogueBytes = 256 << 10

const maxCatalogueEntries = 200

// CatalogueEntry is one module a catalogue lists.
type CatalogueEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	// URL is the https address of the module.yaml (its signature is at URL + ".sig").
	URL string `json:"url"`
	// Version is the release number the publisher says the module is at (0 = not stated).
	Version int `json:"version,omitempty"`
}

// Catalogue is the parsed index.json.
type Catalogue struct {
	Modules []CatalogueEntry `json:"modules"`
}

var catIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ParseCatalogue reads and validates a catalogue. Text is cut to sensible lengths: it is shown to an admin but
// comes from a remote file.
func ParseCatalogue(b []byte) (*Catalogue, error) {
	var c Catalogue
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("the catalogue is not valid JSON: %w", err)
	}
	if len(c.Modules) > maxCatalogueEntries {
		return nil, fmt.Errorf("the catalogue lists %d modules; at most %d are read", len(c.Modules), maxCatalogueEntries)
	}
	seen := map[string]bool{}
	for i := range c.Modules {
		e := &c.Modules[i]
		if !catIDRe.MatchString(e.ID) {
			return nil, fmt.Errorf("catalogue entry %d: %q is not a module id", i+1, e.ID)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("catalogue lists %q twice", e.ID)
		}
		seen[e.ID] = true
		u, err := url.Parse(e.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("catalogue entry %q: url must be a plain https:// address", e.ID)
		}
		e.Name = clip(e.Name, 80)
		e.Description = clip(e.Description, 300)
		if e.Version < 0 {
			e.Version = 0
		}
	}
	return &c, nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// FetchCatalogue downloads and parses the catalogue at rawURL (https only, size capped).
func FetchCatalogue(ctx context.Context, rawURL string, client *http.Client) (*Catalogue, error) {
	b, err := fetchCapped(ctx, rawURL, client, MaxCatalogueBytes)
	if err != nil {
		return nil, err
	}
	c, err := ParseCatalogue(b)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	return c, nil
}
