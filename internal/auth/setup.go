package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
)

// ErrBadSetupCode is returned when the setup code does not match.
var ErrBadSetupCode = errors.New("auth: wrong setup code")

// Setup is first-run setup: while the users file has no users, the first
// admin can be created from the browser by someone who holds the setup code.
//
// The code is printed in the server log and kept in CodeFile (mode 0600), so
// only someone with access to the host can read it. Without it, whoever
// reached an internet-facing panel first would become its admin. It is kept
// across restarts until setup completes, then deleted.
type Setup struct {
	Store    *UserStore
	CodeFile string

	mu   sync.Mutex
	code string
}

// Needed reports whether there are no users yet.
func (s *Setup) Needed() bool { return len(s.Store.Snapshot()) == 0 }

// Code returns the setup code, creating and saving one if there is none.
// created is true when it was just made, so the caller can log it.
func (s *Setup) Code() (code string, created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.code != "" {
		return s.code, false, nil
	}
	if b, err := os.ReadFile(s.CodeFile); err == nil {
		if c := strings.TrimSpace(string(b)); c != "" {
			s.code = c
			return c, false, nil
		}
	}
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", false, err
	}
	c := hex.EncodeToString(raw)
	if err := os.WriteFile(s.CodeFile, []byte(c+"\n"), 0o600); err != nil {
		return "", false, err
	}
	s.code = c
	return c, true, nil
}

// Complete creates the first admin if code is right and no user exists yet,
// then forgets the code and reloads the users.
func (s *Setup) Complete(code, username, hash, googleEmail string) error {
	want, _, err := s.Code()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(code)), []byte(want)) != 1 {
		return ErrBadSetupCode
	}
	if err := CreateFirstAdmin(s.Store.Path(), username, hash, googleEmail); err != nil {
		return err
	}
	s.mu.Lock()
	s.code = ""
	s.mu.Unlock()
	_ = os.Remove(s.CodeFile)
	_, err = s.Store.Reload()
	return err
}
