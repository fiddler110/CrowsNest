package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	jwksTTL        = time.Hour
	jwksMinRefetch = time.Minute // an unknown key id can't make the panel hammer the provider
	maxJWKSBytes   = 256 << 10
)

// jwksCache holds each provider's signing keys, fetched from its jwks_uri.
type jwksCache struct {
	mu   sync.Mutex
	sets map[string]*jwkSet
}

type jwkSet struct {
	keys    map[string]crypto.PublicKey // by kid ("" when the provider gives none)
	fetched time.Time
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func (k jwk) public() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err1 := b64(k.N)
		e, err2 := b64(k.E)
		if err1 != nil || err2 != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("bad RSA key")
		}
		exp := 0
		for _, b := range e {
			exp = exp<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, errors.New("unsupported curve " + k.Crv)
		}
		x, err1 := b64(k.X)
		y, err2 := b64(k.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad EC key")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("EC key is not on the curve")
		}
		return pub, nil
	}
	return nil, errors.New("unsupported key type " + k.Kty)
}

func (c *jwksCache) fetch(ctx context.Context, client *http.Client, uri string, now time.Time) (*jwkSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req) // #nosec G704 -- the URL came from the provider's discovery document, saved by an admin
	if err != nil {
		return nil, fmt.Errorf("fetching the provider's signing keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the provider's key set answered %d", resp.StatusCode)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&doc); err != nil {
		return nil, errors.New("the provider's key set is not JSON")
	}
	set := &jwkSet{keys: map[string]crypto.PublicKey{}, fetched: now}
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if pub, err := k.public(); err == nil {
			set.keys[k.Kid] = pub
		}
	}
	if len(set.keys) == 0 {
		return nil, errors.New("the provider's key set holds no usable signing key")
	}
	return set, nil
}

// key returns the public key for kid, fetching or refreshing the set when it is missing, stale, or lacks kid
// (a key rotation), but not more often than jwksMinRefetch.
func (c *jwksCache) key(ctx context.Context, client *http.Client, uri, kid string, now time.Time) (crypto.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sets == nil {
		c.sets = map[string]*jwkSet{}
	}
	set := c.sets[uri]
	if set != nil {
		if pub, ok := set.keys[kid]; ok && now.Sub(set.fetched) < jwksTTL {
			return pub, nil
		}
		if now.Sub(set.fetched) < jwksMinRefetch {
			if pub, ok := set.keys[kid]; ok {
				return pub, nil
			}
			return nil, errors.New("the id_token is signed with a key the provider does not list")
		}
	}
	fresh, err := c.fetch(ctx, client, uri, now)
	if err != nil {
		return nil, err
	}
	c.sets[uri] = fresh
	if pub, ok := fresh.keys[kid]; ok {
		return pub, nil
	}
	return nil, errors.New("the id_token is signed with a key the provider does not list")
}

// verifyJWT checks the signature of an ID token against the provider's published keys. Only RS256 and ES256 are
// accepted (what every mainstream provider signs with); "none" and anything else is refused.
func (c *jwksCache) verifyJWT(ctx context.Context, client *http.Client, uri, token string, now time.Time) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("id_token is not a JWT")
	}
	hb, err := b64(parts[0])
	if err != nil {
		return errors.New("id_token header is not base64url")
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return errors.New("id_token header is not JSON")
	}
	sig, err := b64(parts[2])
	if err != nil || len(sig) == 0 {
		return errors.New("id_token has no signature")
	}
	pub, err := c.key(ctx, client, uri, h.Kid, now)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch h.Alg {
	case "RS256":
		rk, ok := pub.(*rsa.PublicKey)
		if !ok || rsa.VerifyPKCS1v15(rk, crypto.SHA256, digest[:], sig) != nil {
			return errors.New("id_token signature does not verify")
		}
	case "ES256":
		ek, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 || !ecdsa.Verify(ek, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return errors.New("id_token signature does not verify")
		}
	default:
		return fmt.Errorf("id_token is signed with %q, which CrowsNest does not accept (RS256 or ES256)", h.Alg)
	}
	return nil
}
