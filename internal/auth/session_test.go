package auth

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionRoundTrip(t *testing.T) {
	mgr := NewSessionManager([]byte("test-secret-32-bytes-long-enough"), time.Hour)

	session, err := mgr.New("alice")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if session.CSRFToken == "" {
		t.Fatal("New() produced an empty CSRF token")
	}

	token, err := mgr.Encode(session)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	got, err := mgr.Decode(token)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.Username != "alice" || got.CSRFToken != session.CSRFToken {
		t.Fatalf("Decode() = %+v, want username alice with matching csrf token", got)
	}
}

func TestSessionDecode_TamperedSignature(t *testing.T) {
	mgr := NewSessionManager([]byte("secret-a"), time.Hour)
	session, _ := mgr.New("alice")
	token, _ := mgr.Encode(session)

	tampered := token + "x"
	if _, err := mgr.Decode(tampered); err == nil {
		t.Fatal("Decode() error = nil, want error for a tampered token")
	}
}

func TestSessionDecode_WrongSecret(t *testing.T) {
	signed := NewSessionManager([]byte("secret-a"), time.Hour)
	verifier := NewSessionManager([]byte("secret-b"), time.Hour)

	session, _ := signed.New("alice")
	token, _ := signed.Encode(session)

	if _, err := verifier.Decode(token); err == nil {
		t.Fatal("Decode() error = nil, want error when verified with a different secret")
	}
}

func TestSessionDecode_Expired(t *testing.T) {
	mgr := NewSessionManager([]byte("test-secret"), -time.Hour)
	session, _ := mgr.New("alice")
	token, _ := mgr.Encode(session)

	_, err := mgr.Decode(token)
	if err != ErrSessionExpired {
		t.Fatalf("Decode() error = %v, want ErrSessionExpired", err)
	}
}

func TestSessionDecode_RevokedByValidAfter(t *testing.T) {
	mgr := NewSessionManager([]byte("test-secret"), time.Hour)
	session, _ := mgr.New("alice")
	token, _ := mgr.Encode(session)

	mgr.Users = Users{"alice": {Hash: "irrelevant", ValidAfter: time.Now().Add(time.Minute)}}

	_, err := mgr.Decode(token)
	if err != ErrSessionRevoked {
		t.Fatalf("Decode() error = %v, want ErrSessionRevoked once ValidAfter is after IssuedAt", err)
	}
}

func TestSessionDecode_ValidAfterInPastStillAllowed(t *testing.T) {
	mgr := NewSessionManager([]byte("test-secret"), time.Hour)
	session, _ := mgr.New("alice")
	token, _ := mgr.Encode(session)

	mgr.Users = Users{"alice": {Hash: "irrelevant", ValidAfter: time.Now().Add(-time.Minute)}}

	if _, err := mgr.Decode(token); err != nil {
		t.Fatalf("Decode() error = %v, want nil when the session was issued after ValidAfter", err)
	}
}

func TestSessionDecode_Malformed(t *testing.T) {
	mgr := NewSessionManager([]byte("test-secret"), time.Hour)
	if _, err := mgr.Decode("not-a-valid-token"); err == nil {
		t.Fatal("Decode() error = nil, want error for a malformed token")
	}
}

func TestDecode_Allowed(t *testing.T) {
	m := NewSessionManager([]byte("0123456789abcdef0123456789abcdef"), time.Hour)
	s, _ := m.New("friend")
	tok, err := m.Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	m.Allowed = func(name string) bool { return name == "friend" }
	if _, err := m.Decode(tok); err != nil {
		t.Fatalf("allowed user: Decode() error = %v", err)
	}
	m.Allowed = func(string) bool { return false }
	if _, err := m.Decode(tok); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("user no longer allowed: Decode() error = %v, want ErrSessionRevoked", err)
	}
}

func TestSessionRenew(t *testing.T) {
	mgr := NewSessionManager([]byte("test-secret-32-bytes-long-enough"), time.Hour)
	mgr.AbsoluteMax = 3 * time.Hour
	renew := func(s Session) (Session, string) {
		rec := httptest.NewRecorder()
		out := mgr.Renew(rec, s)
		return out, rec.Header().Get("Set-Cookie")
	}
	fresh, _ := mgr.New("alice")

	if _, c := renew(fresh); c != "" {
		t.Error("a session just issued was re-signed")
	}

	// Half way through its idle period: renewed for a full period, and the cookie decodes.
	mid := fresh
	mid.IssuedAt = time.Now().UTC().Add(-time.Hour)
	mid.ExpiresAt = time.Now().UTC().Add(20 * time.Minute)
	got, c := renew(mid)
	if c == "" || got.ExpiresAt.Before(time.Now().Add(55*time.Minute)) {
		t.Fatalf("not renewed: cookie=%q expires=%v", c, got.ExpiresAt)
	}
	val := strings.TrimPrefix(strings.SplitN(c, ";", 2)[0], SessionCookieName+"=")
	if dec, err := mgr.Decode(val); err != nil || !dec.IssuedAt.Equal(mid.IssuedAt) {
		t.Errorf("renewed cookie: %+v, %v (sign-in time must not move)", dec, err)
	}

	// Near the absolute limit the renewal is capped, and at the limit it stops.
	old := mid
	old.IssuedAt = time.Now().UTC().Add(-2*time.Hour - 50*time.Minute)
	old.ExpiresAt = time.Now().UTC().Add(5 * time.Minute)
	got, _ = renew(old)
	if limit := old.IssuedAt.Add(3 * time.Hour); !got.ExpiresAt.Equal(limit) {
		t.Errorf("expires %v, want the absolute limit %v", got.ExpiresAt, limit)
	}
	last := old
	last.ExpiresAt = last.IssuedAt.Add(3 * time.Hour)
	if _, c := renew(last); c != "" {
		t.Error("renewed past the absolute limit")
	}

	// Off: no absolute limit beyond the idle time.
	mgr.AbsoluteMax = time.Hour
	if _, c := renew(mid); c != "" {
		t.Error("renewed with sliding sessions off")
	}
}
