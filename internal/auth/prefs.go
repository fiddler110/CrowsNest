package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
)

// PrefsStore keeps the sign-in choices made from the dashboard in a small
// JSON file (nothing secret): whether password sign-in is on, which
// overrides config.yaml's auth.password_login.
type PrefsStore struct {
	path string
	mu   sync.Mutex
	p    prefsFile
}

type prefsFile struct {
	// PasswordLogin nil means "as config.yaml says".
	PasswordLogin *bool `json:"password_login,omitempty"`
}

// NewPrefsStore opens path; a missing file means no choices were made.
func NewPrefsStore(path string) (*PrefsStore, error) {
	s := &PrefsStore{path: path}
	raw, err := os.ReadFile(path) // #nosec G304 -- path derives from the operator's config.yaml
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &s.p); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	return s, nil
}

// PasswordLogin is the saved choice, nil when none was made.
func (s *PrefsStore) PasswordLogin() *bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.p.PasswordLogin
}

// SetPasswordLogin saves the choice; nil forgets it.
func (s *PrefsStore) SetPasswordLogin(v *bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.p
	next.PasswordLogin = v
	out, _ := json.MarshalIndent(next, "", "  ")
	if err := writeFileAtomic(s.path, append(out, '\n')); err != nil {
		return err
	}
	s.p = next
	return nil
}

// Reach says who could still sign in under a proposed setup.
type Reach struct {
	// Locked are users who can sign in now but would not be able to.
	Locked []string
	// AdminsLeft counts admins who could still sign in.
	AdminsLeft int
}

// SignInMethods is which ways of signing in are switched on.
type SignInMethods struct{ Password, Google, OIDC bool }

// Reachability works out who could sign in under the methods after, against
// who can under now. envGoogle is the Google allowlist from the environment.
func Reachability(users Users, envGoogle GoogleUsers, now, after SignInMethods) Reach {
	inEnv := map[string]bool{}
	for _, n := range envGoogle {
		inEnv[n] = true
	}
	names := map[string]UserRecord{}
	for n, r := range users {
		names[n] = r
	}
	for n := range inEnv {
		if _, ok := names[n]; !ok {
			names[n] = UserRecord{}
		}
	}
	can := func(r UserRecord, name string, m SignInMethods) bool {
		return (m.Password && r.Hash != "") || (m.Google && (r.GoogleEmail != "" || inEnv[name])) || (m.OIDC && r.OIDCEmail != "")
	}
	var out Reach
	for n, r := range names {
		was, will := can(r, n, now), can(r, n, after)
		if was && !will {
			out.Locked = append(out.Locked, n)
		}
		if will && r.EffectiveRole() == RoleAdmin {
			out.AdminsLeft++
		}
	}
	sort.Strings(out.Locked)
	return out
}
