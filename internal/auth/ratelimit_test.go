package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiter_AllowsUpToMaxThenBlocks(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("Allow() call %d = false, want true within the limit", i)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("Allow() = true, want false once the limit is exceeded")
	}
}

func TestLimiter_SeparateKeysIndependent(t *testing.T) {
	l := NewLimiter(1, time.Minute)
	if !l.Allow("a") {
		t.Fatal("Allow(a) = false, want true")
	}
	if !l.Allow("b") {
		t.Fatal("Allow(b) = false, want true — different key, independent budget")
	}
}

func TestLimiter_WindowExpires(t *testing.T) {
	l := NewLimiter(1, 20*time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("Allow() = false, want true on first attempt")
	}
	if l.Allow("k") {
		t.Fatal("Allow() = true, want false while still within the window")
	}
	time.Sleep(30 * time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("Allow() = false, want true once the window has elapsed")
	}
}

func TestClientIP_UntrustedIgnoresXFF(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:1234"
	r.Header.Set("X-Forwarded-For", "9.9.9.9")

	got := ClientIP(r, nil)
	if got != "203.0.113.5" {
		t.Fatalf("ClientIP() = %q, want %q (no trusted proxies configured)", got, "203.0.113.5")
	}
}

func TestClientIP_TrustedUsesXFF(t *testing.T) {
	trusted, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies() error = %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 10.0.0.1")

	got := ClientIP(r, trusted)
	if got != "9.9.9.9" {
		t.Fatalf("ClientIP() = %q, want %q (RemoteAddr is a trusted proxy)", got, "9.9.9.9")
	}
}

func TestParseTrustedProxies_Invalid(t *testing.T) {
	if _, err := ParseTrustedProxies([]string{"not-a-cidr"}); err == nil {
		t.Fatal("ParseTrustedProxies() error = nil, want error for an invalid CIDR")
	}
}
