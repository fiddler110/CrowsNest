package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

const (
	testRPID   = "crowsnest.example.com"
	testOrigin = "https://crowsnest.example.com"
)

// softKey is a software authenticator: just enough of one to run both ceremonies.
type softKey struct {
	priv   *ecdsa.PrivateKey
	credID []byte
	count  uint32
}

func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softKey{priv: k, credID: id}
}

func (k *softKey) clientData(t *testing.T, typ, challenge, origin string) []byte {
	b, err := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (k *softKey) authData(flags byte, withKey bool) []byte {
	h := sha256.Sum256([]byte(testRPID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	k.count++
	out = binary.BigEndian.AppendUint32(out, k.count)
	if withKey {
		out = append(out, make([]byte, 16)...) // aaguid
		out = binary.BigEndian.AppendUint16(out, uint16(len(k.credID)))
		out = append(out, k.credID...)
		pt, err := k.priv.PublicKey.Bytes() // 0x04 || X || Y
		if err != nil {
			panic(err)
		}
		x, y := pt[1:33], pt[33:65]
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		out = append(out, cose...)
	}
	return out
}

func (k *softKey) register(t *testing.T, challenge string, flags byte) []byte {
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(flags, true)})
	body, _ := json.Marshal(map[string]any{"id": credB64(k.credID), "rawId": credB64(k.credID), "type": "public-key",
		"response": map[string]any{"attestationObject": credB64(att), "clientDataJSON": credB64(k.clientData(t, "webauthn.create", challenge, testOrigin))}})
	return body
}

func (k *softKey) assert(t *testing.T, challenge string, handle []byte, flags byte, origin string) []byte {
	ad := k.authData(flags, false)
	cd := k.clientData(t, "webauthn.get", challenge, origin)
	cdh := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"id": credB64(k.credID), "rawId": credB64(k.credID), "type": "public-key",
		"response": map[string]any{"authenticatorData": credB64(ad), "clientDataJSON": credB64(cd), "signature": credB64(sig), "userHandle": credB64(handle)}})
	return body
}

func credB64(b []byte) string { return credID(b) }

const (
	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40
)

func passkeyService(t *testing.T) *Service {
	t.Helper()
	svc := newTestService(t)
	store, err := NewPasskeyStore(filepath.Join(t.TempDir(), "passkeys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if svc.Passkeys, err = NewPasskeys(store, testRPID, []string{testOrigin}); err != nil {
		t.Fatal(err)
	}
	return svc
}

func challengeOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &o); err != nil || o.PublicKey.Challenge == "" {
		t.Fatalf("no challenge in %s (%v)", rec.Body, err)
	}
	return o.PublicKey.Challenge
}

func withCookies(req *http.Request, rec *httptest.ResponseRecorder) *http.Request {
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge >= 0 {
			req.AddCookie(c)
		}
	}
	return req
}

// registerKey runs the registration ceremony for alice and returns the handle.
func registerKey(t *testing.T, svc *Service, k *softKey, flags byte) error {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := svc.PasskeyRegisterBegin(rec, "alice"); err != nil {
		t.Fatal(err)
	}
	req := withCookies(httptest.NewRequest(http.MethodPost, "/api/account/passkeys/finish", bytes.NewReader(k.register(t, challengeOf(t, rec), flags))), rec)
	return svc.PasskeyRegisterFinish(httptest.NewRecorder(), req, "alice", "Laptop")
}

func loginWith(t *testing.T, svc *Service, build func(challenge string) []byte) (*httptest.ResponseRecorder, *http.Request, []byte) {
	t.Helper()
	begin := httptest.NewRecorder()
	svc.ServePasskeyLoginBegin(begin, httptest.NewRequest(http.MethodPost, "/login/passkey/begin", nil))
	if begin.Code != http.StatusOK {
		t.Fatalf("begin = %d %s", begin.Code, begin.Body)
	}
	body := build(challengeOf(t, begin))
	req := withCookies(httptest.NewRequest(http.MethodPost, "/login/passkey/finish", bytes.NewReader(body)), begin)
	rec := httptest.NewRecorder()
	svc.ServePasskeyLoginFinish(rec, req)
	return rec, req, body
}

func TestPasskey_RegisterThenSignIn(t *testing.T) {
	svc := passkeyService(t)
	k := newSoftKey(t)
	if err := registerKey(t, svc, k, flagUP|flagUV|flagAT); err != nil {
		t.Fatalf("register: %v", err)
	}
	if svc.Passkeys.Store.Count("alice") != 1 {
		t.Fatal("the passkey was not stored")
	}
	u, _ := svc.Passkeys.Store.user("alice", false)
	rec, _, _ := loginWith(t, svc, func(ch string) []byte { return k.assert(t, ch, u.handle, flagUP|flagUV, testOrigin) })
	if rec.Code != http.StatusOK {
		t.Fatalf("sign in = %d %s", rec.Code, rec.Body)
	}
	found := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("no session cookie after a passkey sign-in")
	}
	if svc.Passkeys.Store.List("alice")[0].LastUsed.IsZero() {
		t.Fatal("last-used was not recorded")
	}
}

func TestPasskey_RegisterRefusesNoUserVerification(t *testing.T) {
	svc := passkeyService(t)
	if err := registerKey(t, svc, newSoftKey(t), flagUP|flagAT); err == nil {
		t.Fatal("a passkey that never verified the user was accepted")
	}
	if svc.Passkeys.Store.Count("alice") != 0 {
		t.Fatal("it was stored anyway")
	}
}

func TestPasskey_SignInRefusals(t *testing.T) {
	svc := passkeyService(t)
	k := newSoftKey(t)
	if err := registerKey(t, svc, k, flagUP|flagUV|flagAT); err != nil {
		t.Fatal(err)
	}
	u, _ := svc.Passkeys.Store.user("alice", false)

	cases := map[string]func(ch string) []byte{
		"no user verification": func(ch string) []byte { return k.assert(t, ch, u.handle, flagUP, testOrigin) },
		"wrong origin":         func(ch string) []byte { return k.assert(t, ch, u.handle, flagUP|flagUV, "https://evil.example.com") },
		"wrong challenge":      func(ch string) []byte { return k.assert(t, "AAAA", u.handle, flagUP|flagUV, testOrigin) },
		"unknown user handle":  func(ch string) []byte { return k.assert(t, ch, []byte("nobody"), flagUP|flagUV, testOrigin) },
		"another key": func(ch string) []byte {
			o := newSoftKey(t)
			o.credID = k.credID
			return o.assert(t, ch, u.handle, flagUP|flagUV, testOrigin)
		},
	}
	for name, build := range cases {
		rec, _, _ := loginWith(t, svc, build)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, rec.Code)
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == SessionCookieName {
				t.Errorf("%s: a session was issued", name)
			}
		}
	}
}

func TestPasskey_CeremonyCannotBeReplayed(t *testing.T) {
	svc := passkeyService(t)
	k := newSoftKey(t)
	if err := registerKey(t, svc, k, flagUP|flagUV|flagAT); err != nil {
		t.Fatal(err)
	}
	u, _ := svc.Passkeys.Store.user("alice", false)
	rec, req, body := loginWith(t, svc, func(ch string) []byte { return k.assert(t, ch, u.handle, flagUP|flagUV, testOrigin) })
	if rec.Code != http.StatusOK {
		t.Fatalf("first = %d", rec.Code)
	}
	// The same cookie and the same response, sent again.
	again := httptest.NewRequest(http.MethodPost, "/login/passkey/finish", bytes.NewReader(body))
	for _, c := range req.Cookies() {
		again.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()
	svc.ServePasskeyLoginFinish(rec2, again)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("a replayed sign-in = %d, want 401", rec2.Code)
	}
}

func TestPasskey_DeletedUserCannotSignIn(t *testing.T) {
	svc := passkeyService(t)
	k := newSoftKey(t)
	if err := registerKey(t, svc, k, flagUP|flagUV|flagAT); err != nil {
		t.Fatal(err)
	}
	u, _ := svc.Passkeys.Store.user("alice", false)
	delete(svc.Users, "alice")
	rec, _, _ := loginWith(t, svc, func(ch string) []byte { return k.assert(t, ch, u.handle, flagUP|flagUV, testOrigin) })
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a passkey of a removed user signed in: %d", rec.Code)
	}
}

func TestPasskey_FinishWithoutBeginIsRefused(t *testing.T) {
	svc := passkeyService(t)
	rec := httptest.NewRecorder()
	svc.ServePasskeyLoginFinish(rec, httptest.NewRequest(http.MethodPost, "/login/passkey/finish", bytes.NewReader([]byte("{}"))))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestPasskeyStore_RemoveAndPersist(t *testing.T) {
	svc := passkeyService(t)
	k := newSoftKey(t)
	if err := registerKey(t, svc, k, flagUP|flagUV|flagAT); err != nil {
		t.Fatal(err)
	}
	re, err := NewPasskeyStore(svc.Passkeys.Store.path)
	if err != nil || re.Count("alice") != 1 {
		t.Fatalf("not persisted: %v", err)
	}
	if err := re.Remove("alice", "nope"); err != ErrNoPasskey {
		t.Fatalf("remove unknown = %v", err)
	}
	if err := re.Remove("alice", re.List("alice")[0].ID); err != nil || re.Count("alice") != 0 {
		t.Fatalf("remove = %v", err)
	}
}

func TestNewPasskeys_RejectsBadOrigins(t *testing.T) {
	st, _ := NewPasskeyStore(filepath.Join(t.TempDir(), "p.json"))
	for _, o := range []string{"http://crowsnest.example.com", "https://other.example.org", "https://crowsnest.example.com/path", "crowsnest.example.com"} {
		if _, err := NewPasskeys(st, testRPID, []string{o}); err == nil {
			t.Errorf("origin %q was accepted", o)
		}
	}
	if _, err := NewPasskeys(st, "localhost", []string{"http://localhost:8080"}); err != nil {
		t.Errorf("localhost over http should be allowed: %v", err)
	}
}
