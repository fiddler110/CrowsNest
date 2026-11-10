package dockerguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A bind source below a folder another container can write is a place that
// container can plant a symlink (to /, say), and the engine follows symlinks
// when it binds. So managed binds may never nest: not within one scope, not
// across scopes, not inside an operator scope's bind.
func TestManagedBindsNeverNest(t *testing.T) {
	p, err := ParsePolicy([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	within := strings.Replace(scopeJSON("valheim", "lloesche/valheim-server", ""), `"binds":["/srv/games/valheim"]`,
		`"binds":["/srv/games/valheim","/srv/games/valheim/data"]`, 1)
	if err := p.Admit(mustScope(t, within)); err == nil || !strings.Contains(err.Error(), "inside") {
		t.Errorf("a scope binding a folder and a folder inside it was admitted: %v", err)
	}
	siblings := strings.Replace(scopeJSON("valheim", "lloesche/valheim-server", ""), `"binds":["/srv/games/valheim"]`,
		`"binds":["/srv/games/valheim/config","/srv/games/valheim/data","/srv/games/valheimx"]`, 1)
	if err := p.Admit(mustScope(t, siblings)); err != nil {
		t.Errorf("sibling binds were refused: %v", err)
	}

	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	managed := filepath.Join(dir, "scopes.json")
	if err := os.WriteFile(pol, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	inner := strings.Replace(scopeJSON("gs-two", "lloesche/valheim-server", ""), "/srv/games/gs-two", "/srv/games/valheim/x", 1)
	outer := strings.Replace(scopeJSON("gs-three", "lloesche/valheim-server", ""), "/srv/games/gs-three", "/srv/games/gs-one", 1)
	same := strings.Replace(scopeJSON("gs-four", "lloesche/valheim-server", ""), "/srv/games/gs-four", "/srv/games/valheim", 1)
	file := "[" + scopeJSON("valheim", "lloesche/valheim-server", "") + "," + inner + "," + same + "," + outer + "]"
	if err := os.WriteFile(managed, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	base := `[{"name":"panel-own","images":["crowsnest/x"],"binds":["/srv/games/gs-one/world"]}]`
	res, err := Sources{Base: base, ManagedFile: managed, PolicyFile: pol}.Load()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range res.Scopes {
		got = append(got, s.Name)
	}
	if strings.Join(got, ",") != "panel-own,valheim,gs-four" || len(res.Rejected) != 2 {
		t.Fatalf("scopes in force %v, rejected %v; want panel-own,valheim,gs-four with gs-two and gs-three rejected", got, res.Rejected)
	}
	for _, e := range res.Rejected {
		if !strings.Contains(e.Error(), "inside") {
			t.Errorf("rejection does not say why: %v", e)
		}
	}
}
