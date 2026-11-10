package dockerguard

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Sources is where a guard's scopes come from.
//
// Base is the operator's own GUARD_SCOPES JSON: trusted, unrestricted, and
// only read at start. ManagedFile is a scopes file the dashboard may rewrite;
// every scope in it must fit PolicyFile or it is not loaded. Policy is read
// only, by the operator, and never by anything the panel can write.
type Sources struct {
	Base        string
	ManagedFile string
	PolicyFile  string
}

// Result is one load of the sources.
type Result struct {
	Scopes   []*Scope
	Managed  int     // how many of Scopes came from the managed file
	Rejected []error // managed scopes that did not fit the policy

	sig [sha256.Size]byte // the files' signature taken before they were read
}

// Load builds the scopes in force. A bad base, policy or managed file is an
// error (the previous scopes, if any, stay in force); an individual managed
// scope outside the policy is only rejected and reported.
func (s Sources) Load() (*Result, error) {
	res := Result{sig: s.signature()}
	if strings.TrimSpace(s.Base) != "" {
		base, err := LoadScopes(s.Base)
		if err != nil {
			return nil, err
		}
		res.Scopes = base
	}
	if s.ManagedFile == "" {
		if len(res.Scopes) == 0 {
			return nil, errors.New("the guard needs GUARD_SCOPES or GUARD_SCOPES_FILE")
		}
		return &res, nil
	}
	if s.PolicyFile == "" {
		return nil, errors.New("GUARD_SCOPES_FILE needs GUARD_POLICY: managed scopes are only loaded inside an operator policy")
	}
	pol, err := LoadPolicy(s.PolicyFile)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(s.ManagedFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	managed, err := loadManaged(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.ManagedFile, err)
	}
	taken := map[string]bool{}
	for _, b := range res.Scopes {
		taken[b.Name] = true
	}
	for _, m := range managed {
		switch {
		case taken[m.Name]:
			res.Rejected = append(res.Rejected, fmt.Errorf("managed scope %s: the operator's own scopes already use that name", m.Name))
		case res.Managed >= pol.MaxScopes:
			res.Rejected = append(res.Rejected, fmt.Errorf("managed scope %s: over the policy's max_scopes (%d)", m.Name, pol.MaxScopes))
		default:
			if err := pol.Admit(m); err != nil {
				res.Rejected = append(res.Rejected, fmt.Errorf("managed scope %s: %w", m.Name, err))
				continue
			}
			if err := nestsIn(m, res.Scopes); err != nil {
				res.Rejected = append(res.Rejected, fmt.Errorf("managed scope %s: %w", m.Name, err))
				continue
			}
			m.pinDigest = pol.PinDigests
			m.needsOwner = len(pol.Names) == 0 && pol.exception(m.Name) == nil
			taken[m.Name] = true
			res.Scopes = append(res.Scopes, m)
			res.Managed++
		}
	}
	return &res, nil
}

// nestsIn is an error when a bind of s is inside a bind of a scope already in
// force, or holds one (see NestedBinds). The operator's own scopes count too.
func nestsIn(s *Scope, admitted []*Scope) error {
	for _, o := range admitted {
		for _, a := range s.Binds {
			for _, b := range o.Binds {
				if err := NestedBinds(a, b); err != nil {
					return fmt.Errorf("%w; %s binds it", err, o.Name)
				}
			}
		}
	}
	return nil
}

// loadManaged parses the managed file: a missing or empty file or "[]" is no
// scopes (a fresh install); anything else must parse exactly as GUARD_SCOPES.
func loadManaged(raw string) ([]*Scope, error) {
	t := strings.TrimSpace(raw)
	if t == "" || t == "[]" {
		return nil, nil
	}
	return LoadScopes(t)
}

// signature identifies the bytes of the files a load depends on.
func (s Sources) signature() [sha256.Size]byte {
	h := sha256.New()
	for _, f := range []string{s.ManagedFile, s.PolicyFile} {
		b, err := os.ReadFile(f) // #nosec G304 -- operator-supplied paths
		if err != nil {
			b = []byte("missing:" + f)
		}
		h.Write([]byte(f))
		h.Write(b)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Watch reloads the managed scopes into g whenever the managed or policy file
// changes (checked every interval) or a value arrives on kick (SIGHUP). A
// load that fails leaves the scopes in force exactly as they were. It returns
// when ctx ends. since is the Result the guard started from, so a change made
// between that load and this call is still noticed.
func (g *Guard) Watch(ctx context.Context, s Sources, interval time.Duration, kick <-chan struct{}, since *Result) {
	last := since.sig
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
			last = s.signature()
		case <-t.C:
			sig := s.signature()
			if sig == last {
				continue
			}
			last = sig
		}
		res, err := s.Load()
		if err != nil {
			g.logf("RELOAD failed, keeping the current scopes: %v", err)
			continue
		}
		for _, e := range res.Rejected {
			g.logf("RELOAD rejected %v", e)
		}
		g.SetScopes(res.Scopes)
		g.logf("RELOAD %d scope(s) in force (%d managed, %d rejected)", len(res.Scopes), res.Managed, len(res.Rejected))
	}
}
