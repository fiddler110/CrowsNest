package modules

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(t *testing.T, name string) (seed string, keys []TrustedKey) {
	t.Helper()
	seed, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keys, err = ParseTrustedKeys([]TrustedKey{{Name: name, Key: pub}})
	if err != nil {
		t.Fatal(err)
	}
	return seed, keys
}

func TestSignVerify(t *testing.T) {
	seed, keys := testKey(t, "me")
	body := []byte("api_version: 1\nid: x\n")
	sig, err := Sign(seed, body)
	if err != nil {
		t.Fatal(err)
	}
	if by, err := VerifySignature(keys, body, sig); err != nil || by != "me" {
		t.Fatalf("verify = %q, %v", by, err)
	}
	if _, err := VerifySignature(keys, append(body, '#'), sig); !errors.Is(err, ErrNotSigned) {
		t.Errorf("a changed body verified: %v", err)
	}
	_, other := testKey(t, "someone-else")
	if _, err := VerifySignature(other, body, sig); !errors.Is(err, ErrNotSigned) {
		t.Errorf("an untrusted key verified: %v", err)
	}
	for _, junk := range []string{"", "not base64!!", "AAAA"} {
		if _, err := VerifySignature(keys, body, []byte(junk)); !errors.Is(err, ErrNotSigned) {
			t.Errorf("junk signature %q = %v", junk, err)
		}
	}
	if _, err := VerifySignature(nil, body, sig); !errors.Is(err, ErrNotSigned) {
		t.Error("no trusted keys must trust nothing")
	}
}

func TestParseTrustedKeys(t *testing.T) {
	_, pub, _ := GenerateKey()
	for name, in := range map[string][]TrustedKey{
		"bad name":   {{Name: "", Key: pub}},
		"short key":  {{Name: "a", Key: "AAAA"}},
		"not base64": {{Name: "a", Key: "***"}},
		"duplicate":  {{Name: "a", Key: pub}, {Name: "a", Key: pub}},
	} {
		if _, err := ParseTrustedKeys(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestFetchSignedAndInstall(t *testing.T) {
	seed, keys := testKey(t, "publisher")
	body, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "mygame", "module.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := Sign(seed, body)
	signed := true
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/m.yaml":
			w.Write(body)
		case "/m.yaml.sig":
			if signed {
				w.Write(sig)
			} else {
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- test server

	got, by, err := FetchSigned(context.Background(), srv.URL+"/m.yaml", client, keys)
	if err != nil || by != "publisher" || string(got) != string(body) {
		t.Fatalf("FetchSigned = %q, %v", by, err)
	}
	dir := t.TempDir()
	m, err := Install(dir, srv.URL+"/m.yaml", got, "", false, by)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := ReadLock(dir)
	if e, ok := l.Find(m.ID); !ok || e.SignedBy != "publisher" {
		t.Errorf("lock entry = %+v", e)
	}

	signed = false
	if _, _, err := FetchSigned(context.Background(), srv.URL+"/m.yaml", client, keys); !errors.Is(err, ErrNotSigned) {
		t.Errorf("unsigned module: %v", err)
	}
	_, wrong := testKey(t, "stranger")
	signed = true
	if _, _, err := FetchSigned(context.Background(), srv.URL+"/m.yaml", client, wrong); !errors.Is(err, ErrNotSigned) {
		t.Errorf("signed by an untrusted key: %v", err)
	}
}

func TestPublicClientRefusesPrivateAddresses(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "10.0.0.2", "192.168.1.1", "172.16.5.5", "169.254.169.254", "100.100.1.1", "0.0.0.0", "::1", "fd00::1", "::ffff:10.0.0.1", "fe80::1"} {
		if isPublic(netip.MustParseAddr(a)) {
			t.Errorf("%s counted as public", a)
		}
	}
	for _, a := range []string{"1.1.1.1", "8.8.8.8", "140.82.112.3", "2606:4700:4700::1111"} {
		if !isPublic(netip.MustParseAddr(a)) {
			t.Errorf("%s counted as private", a)
		}
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) }))
	defer srv.Close()
	_, err := Fetch(context.Background(), srv.URL+"/m.yaml", PublicClient())
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("fetch from loopback = %v", err)
	}
}

func TestInstallUpdate_NoDowngradeAndSignerPinned(t *testing.T) {
	base, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "mygame", "module.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	withVersion := func(v int) []byte {
		return []byte(fmt.Sprintf("version: %d\n%s", v, base))
	}
	dir := t.TempDir()
	v2 := withVersion(2)
	if _, err := Install(dir, "https://x/m.yaml", v2, "", false, "alice"); err != nil {
		t.Fatal(err)
	}
	l, _ := ReadLock(dir)
	if e, _ := l.Find("mygame"); e.Version != 2 {
		t.Fatalf("lock version = %d, want 2", e.Version)
	}
	for name, tc := range map[string]struct {
		body []byte
		by   string
		ok   bool
	}{
		"newer release, same signer":      {withVersion(3), "alice", true},
		"same bytes restored":             {v2, "alice", true},
		"older signed release (rollback)": {withVersion(1), "alice", false},
		"unversioned replaces versioned":  {base, "alice", false},
		"different bytes, same release":   {append(withVersion(2), '\n'), "alice", false},
		"another trusted key signs it":    {withVersion(3), "bob", false},
		"newer release but no signature":  {withVersion(3), "", false},
	} {
		d := t.TempDir()
		if _, err := Install(d, "https://x/m.yaml", v2, "", false, "alice"); err != nil {
			t.Fatal(err)
		}
		_, err := Install(d, "https://x/m.yaml", tc.body, "", true, tc.by)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tc.ok)
		}
	}
	// Hash-pinned (never signed) installs are the operator's own review each time: no pin applies.
	d := t.TempDir()
	if _, err := Install(d, "https://x/m.yaml", v2, "", false, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(d, "https://x/m.yaml", withVersion(1), "", true, "alice"); err != nil {
		t.Errorf("update of an unsigned install: %v", err)
	}
}
