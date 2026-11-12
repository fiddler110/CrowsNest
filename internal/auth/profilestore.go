package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// MaxDisplayName is the longest display name, in characters.
const MaxDisplayName = 40

// ProfileStore keeps each person's own choices about how they appear (today just a display name) in a small JSON
// file. The sign-in name never changes: it is what the users file, the audit log and the game permissions use.
type ProfileStore struct {
	path string
	mu   sync.Mutex
	m    map[string]string
}

// NewProfileStore opens path; a missing file means nobody has set a name. An empty path keeps them in memory.
func NewProfileStore(path string) (*ProfileStore, error) {
	s := &ProfileStore{path: path, m: map[string]string{}}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path derives from the operator's config.yaml
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: read %s: %w", path, err)
	}
	var f struct {
		DisplayNames map[string]string `json:"display_names"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	for k, v := range f.DisplayNames {
		s.m[k] = v
	}
	return s, nil
}

// DisplayName is the saved name, "" when none. Nil-safe.
func (s *ProfileStore) DisplayName(user string) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[user]
}

// CleanDisplayName trims name and refuses one that is too long or holds control characters.
func CleanDisplayName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > MaxDisplayName {
		return "", fmt.Errorf("a display name is at most %d characters", MaxDisplayName)
	}
	for _, r := range name {
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			return "", fmt.Errorf("a display name cannot hold control or hidden characters")
		}
	}
	return name, nil
}

// SetDisplayName saves name for user; "" forgets it.
func (s *ProfileStore) SetDisplayName(user, name string) error {
	name, err := CleanDisplayName(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]string, len(s.m)+1)
	for k, v := range s.m {
		next[k] = v
	}
	if name == "" {
		delete(next, user)
	} else {
		next[user] = name
	}
	if s.path != "" {
		out, _ := json.MarshalIndent(struct {
			DisplayNames map[string]string `json:"display_names"`
		}{next}, "", "  ")
		if err := writeFileAtomic(s.path, append(out, '\n')); err != nil {
			return err
		}
	}
	s.m = next
	return nil
}
