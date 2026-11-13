package auth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/fiddler110/crowsnest/internal/atomicfile"
	"github.com/fiddler110/crowsnest/internal/audit"
)

// Passkeys (WebAuthn) are a sign-in method of their own: one touch or biometric on a device the person holds, with no
// password. The authenticator checks the person (user verification is required), so it counts as both factors and
// skips the authenticator-app step. The file holds only public keys and credential ids, so nothing in it can sign
// anyone in; it is still kept 0600.

const (
	passkeyRegCookie   = "crowsnest_pk_reg"
	passkeyLoginCookie = "crowsnest_pk_login"
	passkeyCeremonyTTL = 5 * time.Minute
	// MaxPasskeysPerUser keeps one account from growing the file without bound.
	MaxPasskeysPerUser = 10
)

// ErrNoPasskey means the user has no passkey with that id.
var ErrNoPasskey = errors.New("no such passkey")

// PasskeyInfo is what the Account page shows about one passkey. Nothing secret.
type PasskeyInfo struct {
	ID       string    `json:"id"` // base64url credential id
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used,omitzero"`
}

type storedPasskey struct {
	Name     string              `json:"name"`
	Created  time.Time           `json:"created"`
	LastUsed time.Time           `json:"last_used,omitzero"`
	Cred     webauthn.Credential `json:"cred"`
}

type passkeyUser struct {
	Handle []byte          `json:"handle"` // the WebAuthn user handle: random, never the name
	Keys   []storedPasskey `json:"keys"`
}

// PasskeyStore keeps each user's passkeys in a JSON file.
type PasskeyStore struct {
	path  string
	mu    sync.Mutex
	users map[string]*passkeyUser
}

// NewPasskeyStore opens the file; a missing file means nobody has a passkey.
func NewPasskeyStore(path string) (*PasskeyStore, error) {
	s := &PasskeyStore{path: path, users: map[string]*passkeyUser{}}
	raw, err := os.ReadFile(path) // #nosec G304 -- derived from the operator's config.yaml
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("passkeys: read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &s.users); err != nil {
		return nil, fmt.Errorf("passkeys: parse %s: %w", path, err)
	}
	return s, nil
}

func (s *PasskeyStore) saveLocked() error {
	out, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(s.path, append(out, '\n'), 0o600)
}

// Count is how many passkeys user has.
func (s *PasskeyStore) Count(user string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.users[user]; u != nil {
		return len(u.Keys)
	}
	return 0
}

// List returns user's passkeys, oldest first.
func (s *PasskeyStore) List(user string) []PasskeyInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []PasskeyInfo{}
	if u := s.users[user]; u != nil {
		for _, k := range u.Keys {
			out = append(out, PasskeyInfo{ID: credID(k.Cred.ID), Name: k.Name, Created: k.Created, LastUsed: k.LastUsed})
		}
	}
	return out
}

func credID(b []byte) string { return protocol.URLEncodedBase64(b).String() }

// webUser is the library's view of one account.
type webUser struct {
	name   string
	handle []byte
	creds  []webauthn.Credential
}

func (u webUser) WebAuthnID() []byte                         { return u.handle }
func (u webUser) WebAuthnName() string                       { return u.name }
func (u webUser) WebAuthnDisplayName() string                { return u.name }
func (u webUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// user returns the account's library view. create makes the user handle on first use.
func (s *PasskeyStore) user(name string, create bool) (webUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[name]
	if u == nil {
		if !create {
			return webUser{name: name}, nil
		}
		h := make([]byte, 32)
		if _, err := rand.Read(h); err != nil {
			return webUser{}, err
		}
		u = &passkeyUser{Handle: h}
		s.users[name] = u
	}
	wu := webUser{name: name, handle: u.Handle}
	for _, k := range u.Keys {
		wu.creds = append(wu.creds, k.Cred)
	}
	return wu, nil
}

// byHandle finds the account a user handle belongs to.
func (s *PasskeyStore) byHandle(handle []byte) (webUser, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, u := range s.users {
		if len(u.Keys) > 0 && string(u.Handle) == string(handle) {
			wu := webUser{name: name, handle: u.Handle}
			for _, k := range u.Keys {
				wu.creds = append(wu.creds, k.Cred)
			}
			return wu, true
		}
	}
	return webUser{}, false
}

func (s *PasskeyStore) add(user, name string, cred *webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[user]
	if u == nil {
		return errors.New("passkeys: unknown user")
	}
	if len(u.Keys) >= MaxPasskeysPerUser {
		return fmt.Errorf("you can keep at most %d passkeys: remove one first", MaxPasskeysPerUser)
	}
	for _, k := range u.Keys {
		if string(k.Cred.ID) == string(cred.ID) {
			return errors.New("that passkey is already registered")
		}
	}
	u.Keys = append(u.Keys, storedPasskey{Name: name, Created: time.Now().UTC(), Cred: *cred})
	return s.saveLocked()
}

// touch records a use and the authenticator's new signature counter.
func (s *PasskeyStore) touch(user string, cred *webauthn.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.users[user]; u != nil {
		for i := range u.Keys {
			if string(u.Keys[i].Cred.ID) == string(cred.ID) {
				u.Keys[i].Cred = *cred
				u.Keys[i].LastUsed = time.Now().UTC()
			}
		}
		_ = s.saveLocked()
	}
}

// Remove deletes one passkey by its base64url id.
func (s *PasskeyStore) Remove(user, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[user]
	if u == nil {
		return ErrNoPasskey
	}
	for i, k := range u.Keys {
		if credID(k.Cred.ID) == id {
			u.Keys = append(u.Keys[:i:i], u.Keys[i+1:]...)
			return s.saveLocked()
		}
	}
	return ErrNoPasskey
}

// RemoveAll drops every passkey of a user (used when the user is deleted).
func (s *PasskeyStore) RemoveAll(user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[user]; !ok {
		return nil
	}
	delete(s.users, user)
	return s.saveLocked()
}

// Passkeys is the relying-party side: it runs the two ceremonies.
type Passkeys struct {
	Store *PasskeyStore
	wa    *webauthn.WebAuthn

	usedMu sync.Mutex
	used   map[string]int64 // challenges already answered, until they would have expired anyway
}

// firstUse reports whether this challenge has not been answered before and marks it answered, so a captured
// ceremony cannot be replayed inside its five minutes (the cookie that carries it is otherwise stateless).
func (p *Passkeys) firstUse(challenge string, exp int64) bool {
	p.usedMu.Lock()
	defer p.usedMu.Unlock()
	now := time.Now().Unix()
	for k, e := range p.used {
		if e < now {
			delete(p.used, k)
		}
	}
	if _, seen := p.used[challenge]; seen {
		return false
	}
	if p.used == nil {
		p.used = map[string]int64{}
	}
	p.used[challenge] = exp
	return true
}

// NewPasskeys sets up the relying party. rpID is the site's registrable domain or host ("crowsnest.example.com") and
// origins the exact origins browsers use ("https://crowsnest.example.com"). Both are fixed by the operator: a
// passkey is bound to them, so they are never taken from a request.
func NewPasskeys(store *PasskeyStore, rpID string, origins []string) (*Passkeys, error) {
	if len(origins) == 0 || rpID == "" {
		return nil, errors.New("passkeys need an rp_id and at least one origin")
	}
	for _, o := range origins {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "localhost")) || u.Path != "" {
			return nil, fmt.Errorf("passkey origin %q must be https://host[:port] (http only for localhost)", o)
		}
		if h := u.Hostname(); h != rpID && !strings.HasSuffix(h, "."+rpID) {
			return nil, fmt.Errorf("passkey origin %q is not under rp_id %q", o, rpID)
		}
	}
	wa, err := webauthn.New(&webauthn.Config{RPDisplayName: "CrowsNest", RPID: rpID, RPOrigins: origins})
	if err != nil {
		return nil, err
	}
	return &Passkeys{Store: store, wa: wa}, nil
}

type pkCeremony struct {
	User    string               `json:"u,omitempty"`
	Session webauthn.SessionData `json:"s"`
	Exp     int64                `json:"e"`
}

func (s *Service) setPKCookie(w http.ResponseWriter, name, path string, c pkCeremony, purpose string) error {
	token, err := s.Sessions.signPurpose(purpose, c)
	if err != nil {
		return err
	}
	// #nosec G124 -- HttpOnly and SameSite=Strict; Secure follows server.secure_cookies, as for the session cookie
	http.SetCookie(w, &http.Cookie{Name: name, Value: token, Path: path, MaxAge: int(passkeyCeremonyTTL.Seconds()),
		HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode})
	return nil
}

func (s *Service) takePKCookie(w http.ResponseWriter, r *http.Request, name, path, purpose string) (pkCeremony, bool) {
	var c pkCeremony
	ck, err := r.Cookie(name)
	// #nosec G124 -- clears the cookie; same attributes as when it was set
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: path, MaxAge: -1, Expires: time.Unix(0, 0),
		HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode})
	if err != nil || s.Sessions.verifyPurpose(purpose, ck.Value, &c) != nil || time.Now().Unix() > c.Exp {
		return c, false
	}
	return c, s.Passkeys.firstUse(c.Session.Challenge, c.Exp)
}

// PasskeyRegisterBegin starts adding a passkey for the signed-in user and writes the browser's creation options.
func (s *Service) PasskeyRegisterBegin(w http.ResponseWriter, user string) error {
	u, err := s.Passkeys.Store.user(user, true)
	if err != nil {
		return err
	}
	if len(u.creds) >= MaxPasskeysPerUser {
		return fmt.Errorf("you can keep at most %d passkeys: remove one first", MaxPasskeysPerUser)
	}
	opts, sd, err := s.Passkeys.wa.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}),
		webauthn.WithExclusions(webauthn.Credentials(u.creds).CredentialDescriptors()))
	if err != nil {
		return err
	}
	if err := s.setPKCookie(w, passkeyRegCookie, "/api/account/passkeys", pkCeremony{User: user, Session: *sd, Exp: time.Now().Add(passkeyCeremonyTTL).Unix()}, "passkey-reg"); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	return json.NewEncoder(w).Encode(opts)
}

// PasskeyRegisterFinish checks the browser's answer and stores the new passkey under name.
func (s *Service) PasskeyRegisterFinish(w http.ResponseWriter, r *http.Request, user, name string) error {
	c, ok := s.takePKCookie(w, r, passkeyRegCookie, "/api/account/passkeys", "passkey-reg")
	if !ok || c.User != user {
		return errors.New("that took too long: start again")
	}
	u, err := s.Passkeys.Store.user(user, false)
	if err != nil {
		return err
	}
	cred, err := s.Passkeys.wa.FinishRegistration(u, c.Session, r)
	if err != nil {
		return fmt.Errorf("the browser's answer was not accepted: %w", err)
	}
	if !cred.Flags.UserVerified {
		return errors.New("that device did not check who you are (PIN, fingerprint or face): it can't be used as a passkey")
	}
	return s.Passkeys.Store.add(user, name, cred)
}

// ServePasskeyLoginBegin starts a sign-in with no username: the browser offers whatever passkeys it holds for this
// site. Anyone can call it; it creates nothing but a short signed challenge.
func (s *Service) ServePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if s.Passkeys == nil {
		http.NotFound(w, r)
		return
	}
	if s.throttled(ClientIP(r, s.TrustedProxies), "") {
		http.Error(w, "too many login attempts, try again later", http.StatusTooManyRequests)
		return
	}
	opts, sd, err := s.Passkeys.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err == nil {
		err = s.setPKCookie(w, passkeyLoginCookie, "/login/passkey", pkCeremony{Session: *sd, Exp: time.Now().Add(passkeyCeremonyTTL).Unix()}, "passkey-login")
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(opts)
}

// ServePasskeyLoginFinish verifies the signed challenge and starts the session. The user comes from the passkey's own
// user handle, never from anything the client claims; the account must still exist in the users file.
func (s *Service) ServePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if s.Passkeys == nil {
		http.NotFound(w, r)
		return
	}
	ip := ClientIP(r, s.TrustedProxies)
	if s.throttled(ip, "") {
		http.Error(w, "too many login attempts, try again later", http.StatusTooManyRequests)
		return
	}
	c, ok := s.takePKCookie(w, r, passkeyLoginCookie, "/login/passkey", "passkey-login")
	if !ok {
		http.Error(w, "your sign-in expired: try again", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var found webUser
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		u, ok := s.Passkeys.Store.byHandle(userHandle)
		if !ok {
			return nil, errors.New("unknown passkey")
		}
		found = u
		return u, nil
	}
	cred, err := s.Passkeys.wa.FinishDiscoverableLogin(handler, c.Session, r)
	if err != nil || found.name == "" {
		s.failed(ip, "")
		audit.Printf("passkey sign-in refused: %v", err)
		http.Error(w, "that passkey was not accepted", http.StatusUnauthorized)
		return
	}
	if !cred.Flags.UserVerified || cred.Authenticator.CloneWarning {
		s.failed(ip, found.name)
		audit.Printf("%q passkey sign-in refused (user verification missing or cloned authenticator)", found.name)
		http.Error(w, "that passkey was not accepted", http.StatusUnauthorized)
		return
	}
	var known bool
	if s.Store != nil {
		_, known = s.Store.Lookup(found.name)
	} else {
		_, known = s.Users[found.name]
	}
	if !known {
		http.Error(w, "that passkey was not accepted", http.StatusUnauthorized)
		return
	}
	s.Passkeys.Store.touch(found.name, cred)
	session, err := s.newSession(w, r, found.name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Printf("%q signed in with a passkey", found.name)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResponse{CSRFToken: session.CSRFToken})
}
