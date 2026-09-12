package auth

import (
	"testing"
	"time"
)

func TestSessionRoundTrip(t *testing.T) {
	mgr := NewSessionManager([]byte("test-secret-32-bytes-long-enough"), time.Hour)

	session, err := mgr.New("scott")
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
	if got.Username != "scott" || got.CSRFToken != session.CSRFToken {
		t.Fatalf("Decode() = %+v, want username scott with matching csrf token", got)
	}
}

func TestSessionDecode_TamperedSignature(t *testing.T) {
	mgr := NewSessionManager([]byte("secret-a"), time.Hour)
	session, _ := mgr.New("scott")
	token, _ := mgr.Encode(session)

	tampered := token + "x"
	if _, err := mgr.Decode(tampered); err == nil {
		t.Fatal("Decode() error = nil, want error for a tampered token")
	}
}

func TestSessionDecode_WrongSecret(t *testing.T) {
	signed := NewSessionManager([]byte("secret-a"), time.Hour)
	verifier := NewSessionManager([]byte("secret-b"), time.Hour)

	session, _ := signed.New("scott")
	token, _ := signed.Encode(session)

	if _, err := verifier.Decode(token); err == nil {
		t.Fatal("Decode() error = nil, want error when verified with a different secret")
	}
}

func TestSessionDecode_Expired(t *testing.T) {
	mgr := NewSessionManager([]byte("test-secret"), -time.Hour)
	session, _ := mgr.New("scott")
	token, _ := mgr.Encode(session)

	_, err := mgr.Decode(token)
	if err != ErrSessionExpired {
		t.Fatalf("Decode() error = %v, want ErrSessionExpired", err)
	}
}

func TestSessionDecode_Malformed(t *testing.T) {
	mgr := NewSessionManager([]byte("test-secret"), time.Hour)
	if _, err := mgr.Decode("not-a-valid-token"); err == nil {
		t.Fatal("Decode() error = nil, want error for a malformed token")
	}
}
