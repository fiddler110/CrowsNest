package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signRS256(t *testing.T, key *rsa.PrivateKey, kid, alg string) string {
	t.Helper()
	signing := enc([]byte(`{"alg":"`+alg+`","kid":"`+kid+`"}`)) + "." + enc([]byte(`{"sub":"1"}`))
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(sig)
}

func TestVerifyJWT(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fetches := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": "r1", "use": "sig", "n": enc(rk.N.Bytes()), "e": enc(big.NewInt(int64(rk.E)).Bytes())},
			{"kty": "EC", "kid": "e1", "crv": "P-256", "x": enc(ek.X.Bytes()), "y": enc(ek.Y.Bytes())},
		}})
	}))
	defer srv.Close()
	var c jwksCache
	now := time.Unix(1_800_000_000, 0)
	verify := func(tok string) error { return c.verifyJWT(context.Background(), srv.Client(), srv.URL, tok, now) }

	if err := verify(signRS256(t, rk, "r1", "RS256")); err != nil {
		t.Fatalf("good RS256 token: %v", err)
	}
	if err := verify(signRS256(t, other, "r1", "RS256")); err == nil {
		t.Error("a token signed by another key verified")
	}
	if err := verify(signRS256(t, rk, "r1", "none")); err == nil || !strings.Contains(err.Error(), "does not accept") {
		t.Errorf("alg none = %v, want refused", err)
	}
	if err := verify(signRS256(t, rk, "unknown", "RS256")); err == nil {
		t.Error("an unknown kid verified")
	}
	tampered := signRS256(t, rk, "r1", "RS256")
	parts := strings.Split(tampered, ".")
	if err := verify(parts[0] + "." + enc([]byte(`{"sub":"2"}`)) + "." + parts[2]); err == nil {
		t.Error("a tampered payload verified")
	}

	signing := enc([]byte(`{"alg":"ES256","kid":"e1"}`)) + "." + enc([]byte(`{"sub":"1"}`))
	sum := sha256.Sum256([]byte(signing))
	r, s, _ := ecdsa.Sign(rand.Reader, ek, sum[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	if err := verify(signing + "." + enc(sig)); err != nil {
		t.Errorf("good ES256 token: %v", err)
	}
	if fetches > 2 {
		t.Errorf("fetched the key set %d times, want it cached (one refresh for the unknown kid at most)", fetches)
	}
}
