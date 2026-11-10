package dockerguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pinPalworld marks the palworld scope as a managed scope under pin_digests.
func pinPalworld(g *Guard) { g.cur().byName["palworld"].pinDigest = true }

func TestPinnedScopeCreatesOnlyByDigest(t *testing.T) {
	h := newHarness(t, scopesJSON, pinPalworld)
	for _, image := range []string{"thijsvanloef/palworld-server-docker@" + digest, "docker.io/thijsvanloef/palworld-server-docker@" + digest} {
		body := composeBody(t)
		body["Image"] = image
		if r := h.request("POST", create, body); r.code != 201 {
			t.Errorf("%s: %s", image, r)
		}
	}
	for _, image := range []string{"thijsvanloef/palworld-server-docker:latest", "thijsvanloef/palworld-server-docker",
		"thijsvanloef/palworld-server-docker:latest@" + digest, "thijsvanloef/palworld-server-docker@sha256:abc"} {
		body := composeBody(t)
		body["Image"] = image
		r := h.request("POST", create, body)
		if r.code != 403 {
			t.Errorf("%s under pin_digests: %s, want 403", image, r)
		}
	}
	if !strings.Contains(h.logged(), "must be pinned by digest") {
		t.Errorf("the refusal does not say why:\n%s", h.logged())
	}
	// pulls by tag stay allowed: that is how a new digest is found
	if r := h.request("POST", "/v1.52/images/create?fromImage=thijsvanloef%2Fpalworld-server-docker&tag=latest", nil); r.code != 200 {
		t.Errorf("pull by tag under pin_digests: %s", r)
	}
}

// pin_digests is the policy's, so it reaches managed scopes only; the operator's own scopes are untouched.
func TestPinDigestsAppliesToManagedScopesOnly(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	managed := filepath.Join(dir, "scopes.json")
	if err := os.WriteFile(pol, []byte(testPolicy+"pin_digests: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managed, []byte("["+scopeJSON("valheim", "lloesche/valheim-server", "")+"]"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Sources{Base: `[{"name":"panel-own","images":["crowsnest/x"]}]`, ManagedFile: managed, PolicyFile: pol}.Load()
	if err != nil || len(res.Scopes) != 2 {
		t.Fatalf("load: %+v %v", res, err)
	}
	for _, s := range res.Scopes {
		if want := s.Name == "valheim"; s.pinDigest != want {
			t.Errorf("%s: pinDigest = %v, want %v", s.Name, s.pinDigest, want)
		}
	}
	// without the setting nothing is pinned
	if err := os.WriteFile(pol, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	res, _ = Sources{ManagedFile: managed, PolicyFile: pol}.Load()
	if res.Scopes[0].pinDigest {
		t.Error("pinned without pin_digests")
	}
	// a scope cannot ask for (or out of) pinning itself
	if _, err := LoadScopes(`[{"name":"x","images":["a/b"],"pin_digest":false}]`); err == nil {
		t.Error("a scope key turned pinning off")
	}
}

func TestExamplePolicyPinsDigests(t *testing.T) {
	p, err := LoadPolicy("../../policy.yaml.example")
	if err != nil || !p.PinDigests {
		t.Fatalf("policy.yaml.example: %+v %v", p, err)
	}
}

func TestBaseScopesStillCreateByTagNextToAPinnedOne(t *testing.T) {
	h := newHarness(t, scopesJSON, pinPalworld)
	body := map[string]any{"Image": "lloesche/valheim-server:latest", "HostConfig": map[string]any{"NetworkMode": "crowsnest-games-net"}}
	if r := h.request("POST", "/v1.52/containers/create?name=valheim", body); r.code != 201 {
		t.Errorf("an operator scope was held to pin_digests: %s", r)
	}
}
