package mfa

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/fiddler110/crowsnest/internal/vault"
)

const (
	recoveryCodeCount = 10
	maxFailures       = 5
	lockFor           = 15 * time.Minute
)

// Errors Verify returns. Callers answer all of them the same way to a client
// that is not signed in; the distinction is for the audit log.
var (
	ErrNotEnrolled = errors.New("mfa: not enrolled")
	ErrLocked      = errors.New("mfa: too many wrong codes, try again later")
	ErrBadCode     = errors.New("mfa: wrong code")
)

type record struct {
	Secret      string    `json:"secret"` // sealed
	Enabled     bool      `json:"enabled"`
	Recovery    []string  `json:"recovery,omitempty"` // bcrypt hashes of unused codes
	LastCounter int64     `json:"last_counter,omitempty"`
	Failures    int       `json:"failures,omitempty"`
	LockedUntil time.Time `json:"locked_until,omitempty"`
}

// Store keeps each user's TOTP enrolment in a JSON file with the secrets
// sealed by the vault. Recovery codes are stored only as bcrypt hashes.
type Store struct {
	Now func() time.Time // for tests

	path  string
	vault *vault.Vault
	mu    sync.Mutex
	users map[string]*record
}

// NewStore opens the file at path; a missing file means nobody is enrolled.
func NewStore(path string, v *vault.Vault) (*Store, error) {
	s := &Store{path: path, vault: v, users: map[string]*record{}}
	raw, err := os.ReadFile(path) // #nosec G304 -- path derives from the operator's config.yaml
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mfa: read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &s.users); err != nil {
		return nil, fmt.Errorf("mfa: parse %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func purpose(user string) string { return "totp:" + user }

func (s *Store) saveLocked() error {
	out, err := json.MarshalIndent(s.users, "", "  ") // #nosec G117 -- the TOTP secrets are stored sealed (see vault)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".mfa-*.tmp")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(append(out, '\n'))
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr, os.Chmod(tmp.Name(), 0o600)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// Enabled reports whether user has finished enrolling.
func (s *Store) Enabled(user string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.users[user]
	return r != nil && r.Enabled
}

// RecoveryLeft is how many unused recovery codes user has.
func (s *Store) RecoveryLeft(user string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.users[user]; r != nil {
		return len(r.Recovery)
	}
	return 0
}

// Begin starts (or restarts) enrolment and returns the new secret. Nothing
// is required at sign-in until Confirm succeeds. It refuses if user already
// has a second factor, which must be removed first.
func (s *Store) Begin(user string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.users[user]; r != nil && r.Enabled {
		return "", errors.New("mfa: already set up; turn it off first to set it up again")
	}
	secret, err := GenerateSecret()
	if err != nil {
		return "", err
	}
	sealed, err := s.vault.Seal(purpose(user), secret)
	if err != nil {
		return "", err
	}
	s.users[user] = &record{Secret: sealed}
	return secret, s.saveLocked()
}

// PendingSecret is the secret of an enrolment begun but not confirmed.
func (s *Store) PendingSecret(user string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.users[user]
	if r == nil || r.Enabled {
		return "", false
	}
	secret, _, err := s.vault.Unseal(purpose(user), r.Secret)
	return secret, err == nil
}

// Confirm finishes enrolment when code is right for the pending secret, and
// returns the recovery codes: the only time they are shown.
func (s *Store) Confirm(user, code string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.users[user]
	if r == nil || r.Enabled {
		return nil, ErrNotEnrolled
	}
	if err := s.lockedLocked(r); err != nil {
		return nil, err
	}
	secret, _, err := s.vault.Unseal(purpose(user), r.Secret)
	if err != nil {
		return nil, err
	}
	counter, ok := Verify(secret, code, s.now(), r.LastCounter)
	if !ok {
		s.failLocked(r)
		_ = s.saveLocked()
		return nil, ErrBadCode
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	r.Enabled, r.LastCounter, r.Failures, r.Recovery = true, counter, 0, hashes
	return codes, s.saveLocked()
}

func (s *Store) lockedLocked(r *record) error {
	if s.now().Before(r.LockedUntil) {
		return ErrLocked
	}
	return nil
}

func (s *Store) failLocked(r *record) {
	if r.Failures++; r.Failures >= maxFailures {
		r.LockedUntil, r.Failures = s.now().Add(lockFor), 0
	}
}

// Verify checks a sign-in code: a current TOTP code, or an unused recovery
// code, which is used up. usedRecovery says which it was.
func (s *Store) Verify(user, code string) (usedRecovery bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.users[user]
	if r == nil || !r.Enabled {
		return false, ErrNotEnrolled
	}
	if err := s.lockedLocked(r); err != nil {
		return false, err
	}
	secret, _, err := s.vault.Unseal(purpose(user), r.Secret)
	if err != nil {
		return false, err
	}
	if counter, ok := Verify(secret, code, s.now(), r.LastCounter); ok {
		r.LastCounter, r.Failures = counter, 0
		return false, s.saveLocked()
	}
	norm := normalizeRecovery(code)
	for i, h := range r.Recovery {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(norm)) == nil {
			r.Recovery = append(r.Recovery[:i:i], r.Recovery[i+1:]...)
			r.Failures = 0
			return true, s.saveLocked()
		}
	}
	s.failLocked(r)
	_ = s.saveLocked()
	return false, ErrBadCode
}

// Remove deletes user's second factor (turning it off, or an admin's reset).
func (s *Store) Remove(user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[user]; !ok {
		return nil
	}
	delete(s.users, user)
	return s.saveLocked()
}

// NewRecoveryCodes replaces user's recovery codes with a fresh set, returned
// once. The caller has checked a current code first.
func (s *Store) NewRecoveryCodes(user string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.users[user]
	if r == nil || !r.Enabled {
		return nil, ErrNotEnrolled
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	r.Recovery = hashes
	return codes, s.saveLocked()
}

func normalizeRecovery(c string) string {
	return strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
}

const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no 0/o/1/i/l

// newRecoveryCodes makes ten codes like "k3x9d-m2q7a" (50 bits each) and
// their bcrypt hashes.
func newRecoveryCodes() (codes, hashes []string, err error) {
	for i := 0; i < recoveryCodeCount; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		chars := make([]byte, 10)
		for j, v := range b {
			chars[j] = recoveryAlphabet[int(v)%len(recoveryAlphabet)]
		}
		raw := string(chars)
		h, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, raw[:5]+"-"+raw[5:])
		hashes = append(hashes, string(h))
	}
	return codes, hashes, nil
}
