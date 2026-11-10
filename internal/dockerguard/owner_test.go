package dockerguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ownerPolicy = `
games_root: /srv/games
images: [lloesche/valheim-server]
networks: [crowsnest-games-net]
ports: ["27000-27999/udp"]
`

// Without "names" the policy admits any name, but only for a scope that says its container carries the ownership label.
func TestPolicyWithoutNamesNeedsTheOwnerLabel(t *testing.T) {
	p, err := ParsePolicy([]byte(ownerPolicy))
	if err != nil {
		t.Fatalf("a policy with no names was refused: %v", err)
	}
	owned := scopeJSON("my-valheim", "lloesche/valheim-server", `,"labels":{"`+OwnerLabel+`":"true"}`)
	if err := p.Admit(mustScope(t, owned)); err != nil {
		t.Errorf("an owned scope with a free-form name was refused: %v", err)
	}
	err = p.Admit(mustScope(t, scopeJSON("caddy", "lloesche/valheim-server", "")))
	if err == nil || !strings.Contains(err.Error(), OwnerLabel) {
		t.Errorf("a scope without the label was admitted or the reason is unclear: %v", err)
	}
	// a policy that lists names behaves as before: the label is not needed, other names are refused
	legacy, _ := ParsePolicy([]byte(testPolicy))
	if err := legacy.Admit(mustScope(t, scopeJSON("valheim", "lloesche/valheim-server", ""))); err != nil {
		t.Errorf("listed name refused: %v", err)
	}
	if legacy.Admit(mustScope(t, scopeJSON("caddy", "lloesche/valheim-server", ""))) == nil {
		t.Error("an unlisted name was admitted under a policy with names")
	}
}

// Loaded from files: the scope is marked as needing the label only when the policy has no names.
func TestLoadMarksOwnerScopes(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, "scopes.json")
	js := "[" + scopeJSON("anything", "lloesche/valheim-server", `,"labels":{"`+OwnerLabel+`":"true"}`) + "]"
	if err := os.WriteFile(managed, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	for policy, want := range map[string]bool{ownerPolicy: true, ownerPolicy + "names: [anything]\n": false} {
		pol := filepath.Join(dir, "policy.yaml")
		if err := os.WriteFile(pol, []byte(policy), 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := Sources{ManagedFile: managed, PolicyFile: pol}.Load()
		if err != nil || len(res.Scopes) != 1 {
			t.Fatalf("load: %+v %v", res, err)
		}
		if got := res.Scopes[0].needsOwner; got != want {
			t.Errorf("needsOwner = %v, want %v", got, want)
		}
	}
}

func needOwner(names ...string) func(*Guard) {
	return func(g *Guard) {
		for _, n := range names {
			g.cur().byName[n].needsOwner = true
		}
	}
}

// A scope that needs the label reaches only a container that has it: an unlabelled container of the same name is
// invisible and cannot be started, stopped or inspected, and a create must carry the label.
func TestOwnerScopeOnlyReachesLabelledContainers(t *testing.T) {
	// valheim carries the label, palworld does not
	val := containers[1].(map[string]any)["Labels"].(map[string]any)
	val[OwnerLabel] = "true"
	t.Cleanup(func() { delete(val, OwnerLabel) })

	h := newHarness(t, scopesJSON, needOwner("valheim", "palworld"))
	if r := h.request("POST", "/containers/valheim/start", nil); r.code >= 400 {
		t.Errorf("start of the owned container: %s", r)
	}
	if r := h.request("POST", "/containers/palworld/stop", nil); r.code < 400 {
		t.Errorf("stop of an unlabelled container was allowed: %s", r)
	}
	if n := len(h.reached("POST", "/containers/palworld/stop")); n != 0 {
		t.Errorf("the engine was asked to stop the unlabelled container %d time(s)", n)
	}
	list := h.request("GET", "/containers/json?all=1", nil)
	if !strings.Contains(string(list.raw), "valheim") || strings.Contains(string(list.raw), "palworld") {
		t.Errorf("the list should show valheim only: %s", list)
	}
	// create: a body without the label is refused, with it the create goes through
	body := composeBody(t)
	if r := h.request("POST", create, body); r.code != 403 || !strings.Contains(string(r.raw)+h.logged(), OwnerLabel) {
		t.Errorf("create without the label: %s", r)
	}
	body = composeBody(t)
	body["Labels"].(map[string]any)[OwnerLabel] = "true"
	h2 := newHarness(t, scopesJSON, func(g *Guard) {
		g.cur().byName["palworld"].needsOwner = true
		g.cur().byName["palworld"].Labels[OwnerLabel] = "true"
	})
	if r := h2.request("POST", create, body); r.code != 201 {
		t.Errorf("create with the label: %s", r)
	}
}

// The network listing names containers without labels, so a container that has a scope's name but not its label stays
// out of the view; an owned one is listed.
func TestNetworkViewHidesUnownedNamesakes(t *testing.T) {
	pal := containers[0].(map[string]any)["Labels"].(map[string]any)
	t.Cleanup(func() { delete(pal, OwnerLabel) })
	pal[OwnerLabel] = "true"
	h := newHarness(t, scopesJSON, needOwner("palworld"))
	r := h.request("GET", "/networks/crowsnest-games-net", nil)
	if !strings.Contains(string(r.raw), `"palworld"`) {
		t.Errorf("the owned container is missing from the network view: %s", r)
	}
	delete(pal, OwnerLabel)
	h = newHarness(t, scopesJSON, needOwner("palworld"))
	if r := h.request("GET", "/networks/crowsnest-games-net", nil); strings.Contains(string(r.raw), `"palworld"`) {
		t.Errorf("a namesake without the label is listed: %s", r)
	}
}
