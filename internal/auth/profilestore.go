package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
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
	// devices are the browser/system descriptions each person has signed in from, and notices the latest
	// sign-in from one they had not used before.
	devices map[string][]string
	notices map[string]SignInNotice
}

// SignInNotice records a sign-in from a browser or system the person had not used before.
type SignInNotice struct {
	Device string    `json:"device"`
	IP     string    `json:"ip,omitempty"`
	At     time.Time `json:"at"`
}

// maxKnownDevices bounds the remembered devices per person; the oldest are forgotten first.
const maxKnownDevices = 50

type profileFile struct {
	DisplayNames map[string]string       `json:"display_names"`
	Devices      map[string][]string     `json:"devices,omitempty"`
	Notices      map[string]SignInNotice `json:"notices,omitempty"`
}

// NewProfileStore opens path; a missing file means nobody has set a name. An empty path keeps them in memory.
func NewProfileStore(path string) (*ProfileStore, error) {
	s := &ProfileStore{path: path, m: map[string]string{}, devices: map[string][]string{}, notices: map[string]SignInNotice{}}
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
	var f profileFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	for k, v := range f.DisplayNames {
		s.m[k] = v
	}
	for k, v := range f.Devices {
		s.devices[k] = v
	}
	for k, v := range f.Notices {
		s.notices[k] = v
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

// save writes the three maps; the caller holds mu.
func (s *ProfileStore) save(names map[string]string, devices map[string][]string, notices map[string]SignInNotice) error {
	if s.path == "" {
		return nil
	}
	out, _ := json.MarshalIndent(profileFile{names, devices, notices}, "", "  ")
	return writeFileAtomic(s.path, append(out, '\n'))
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
	if err := s.save(next, s.devices, s.notices); err != nil {
		return err
	}
	s.m = next
	return nil
}

// NoteSignIn remembers that user signed in from device. It reports whether that was a device they had not used
// before, and they had used another (a person's very first sign-in is not news). A new one also becomes the
// person's notice until they dismiss it.
func (s *ProfileStore) NoteSignIn(user, device, ip string, now time.Time) (isNew bool, err error) {
	if s == nil || device == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	known := s.devices[user]
	for _, d := range known {
		if d == device {
			return false, nil
		}
	}
	devices := make(map[string][]string, len(s.devices)+1)
	for k, v := range s.devices {
		devices[k] = v
	}
	list := append(append([]string{}, known...), device)
	if len(list) > maxKnownDevices {
		list = list[len(list)-maxKnownDevices:]
	}
	devices[user] = list
	notices := s.notices
	isNew = len(known) > 0
	if isNew {
		notices = make(map[string]SignInNotice, len(s.notices)+1)
		for k, v := range s.notices {
			notices[k] = v
		}
		notices[user] = SignInNotice{Device: device, IP: ip, At: now.UTC()}
	}
	if err := s.save(s.m, devices, notices); err != nil {
		return false, err
	}
	s.devices, s.notices = devices, notices
	return isNew, nil
}

// SignInNotice returns the person's undismissed notice, if any.
func (s *ProfileStore) SignInNotice(user string) (SignInNotice, bool) {
	if s == nil {
		return SignInNotice{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.notices[user]
	return n, ok
}

// DismissSignInNotice clears the person's notice.
func (s *ProfileStore) DismissSignInNotice(user string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.notices[user]; !ok {
		return nil
	}
	notices := make(map[string]SignInNotice, len(s.notices))
	for k, v := range s.notices {
		if k != user {
			notices[k] = v
		}
	}
	if err := s.save(s.m, s.devices, notices); err != nil {
		return err
	}
	s.notices = notices
	return nil
}
