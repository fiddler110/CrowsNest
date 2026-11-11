// Package mfa is time-based one-time-password (TOTP, RFC 6238) second-factor
// sign-in: the code arithmetic, and an encrypted per-user store with replay
// protection, recovery codes and lockout.
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238's default, and the one every authenticator app supports
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Digits is the length of a code.
	Digits = 6
	// Period is how long one code lasts, in seconds.
	Period = 30
	// secretBytes is 160 bits, the RFC 4226 recommendation.
	secretBytes = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a new random secret, base32 encoded.
func GenerateSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

func counterAt(t time.Time) int64 { return t.Unix() / Period }

func hotp(key []byte, counter int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter)) // #nosec G115 -- counters are positive
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", Digits, v%1_000_000)
}

// Code is the code for secret at t.
func Code(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("mfa: bad secret: %w", err)
	}
	return hotp(key, counterAt(t)), nil
}

// Verify checks code against secret at now, accepting the previous and next
// period for clock drift. A period at or before last (the newest one already
// used) is refused, so a code can't be replayed. It returns the matching
// period to be stored as the new last.
func Verify(secret, code string, now time.Time, last int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != Digits {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return 0, false
	}
	cur := counterAt(now)
	matched := int64(-1)
	for c := cur - 1; c <= cur+1; c++ { // always all three, so timing doesn't say which matched
		if subtle.ConstantTimeCompare([]byte(hotp(key, c)), []byte(code)) == 1 && c > last {
			matched = c
		}
	}
	return matched, matched >= 0
}

// URI is the otpauth:// URI authenticator apps read from a QR code.
func URI(issuer, account, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {fmt.Sprint(Digits)}, "period": {fmt.Sprint(Period)}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}
