package mfa

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/vault"
)

// RFC 6238 appendix B: the SHA-1 secret "12345678901234567890", 8 digits there; the
// last six digits are what a 6-digit code shows.
func TestCodeMatchesRFC6238(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		got, err := Code(secret, time.Unix(ts, 0))
		if err != nil || got != want {
			t.Errorf("Code(t=%d) = %q, %v; want %q", ts, got, err, want)
		}
	}
}

func TestVerifyWindowAndReplay(t *testing.T) {
	secret, _ := GenerateSecret()
	now := time.Unix(1_700_000_000, 0)
	code, _ := Code(secret, now)
	c, ok := Verify(secret, code, now, 0)
	if !ok {
		t.Fatal("current code refused")
	}
	if _, ok := Verify(secret, code, now, c); ok {
		t.Error("a used code was accepted again")
	}
	if _, ok := Verify(secret, code, now.Add(Period*time.Second), 0); !ok {
		t.Error("code one period late refused")
	}
	if _, ok := Verify(secret, code, now.Add(3*Period*time.Second), 0); ok {
		t.Error("code three periods late accepted")
	}
	if _, ok := Verify(secret, "12345", now, 0); ok {
		t.Error("short code accepted")
	}
}

func newTestStore(t *testing.T, now *time.Time) *Store {
	t.Helper()
	dir := t.TempDir()
	v, _ := vault.New("", filepath.Join(dir, "k"))
	s, err := NewStore(filepath.Join(dir, "mfa.json"), v)
	if err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return *now }
	return s
}

func TestEnrolVerifyRecoveryAndLockout(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newTestStore(t, &now)
	secret, err := s.Begin("ann")
	if err != nil {
		t.Fatal(err)
	}
	if s.Enabled("ann") {
		t.Fatal("enabled before confirming")
	}
	raw, _ := os.ReadFile(s.path)
	if strings.Contains(string(raw), secret) {
		t.Fatal("the TOTP secret is stored in plain text")
	}
	if _, err := s.Confirm("ann", "000000"); err != ErrBadCode {
		t.Fatalf("wrong code: %v", err)
	}
	code, _ := Code(secret, now)
	recovery, err := s.Confirm("ann", code)
	if err != nil || len(recovery) != 10 || !s.Enabled("ann") {
		t.Fatalf("Confirm: %v %v", recovery, err)
	}
	raw, _ = os.ReadFile(s.path)
	if strings.Contains(string(raw), strings.ReplaceAll(recovery[0], "-", "")) {
		t.Fatal("recovery codes are stored in plain text")
	}

	// The enrolment code can't be reused to sign in; the next period's can.
	if _, err := s.Verify("ann", code); err != ErrBadCode {
		t.Fatalf("replayed enrolment code: %v", err)
	}
	now = now.Add(Period * time.Second)
	next, _ := Code(secret, now)
	if used, err := s.Verify("ann", next); err != nil || used {
		t.Fatalf("Verify: %v %v", used, err)
	}
	// A recovery code works once, with or without the dash and in any case.
	if used, err := s.Verify("ann", strings.ToUpper(recovery[0])); err != nil || !used {
		t.Fatalf("recovery code: %v %v", used, err)
	}
	if _, err := s.Verify("ann", recovery[0]); err != ErrBadCode {
		t.Fatalf("recovery code reused: %v", err)
	}
	if s.RecoveryLeft("ann") != 9 {
		t.Errorf("recovery left = %d", s.RecoveryLeft("ann"))
	}
	// Five wrong codes lock the account, even against the right one.
	for i := 0; i < 5; i++ {
		s.Verify("ann", "111111")
	}
	now = now.Add(Period * time.Second)
	good, _ := Code(secret, now)
	if _, err := s.Verify("ann", good); err != ErrLocked {
		t.Fatalf("while locked: %v", err)
	}
	now = now.Add(lockFor + time.Minute)
	good, _ = Code(secret, now)
	if _, err := s.Verify("ann", good); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
	// Persisted, and removable.
	s2, _ := NewStore(s.path, s.vault)
	if !s2.Enabled("ann") {
		t.Fatal("not persisted")
	}
	s2.Remove("ann")
	if s2.Enabled("ann") {
		t.Fatal("still enabled after Remove")
	}
}
