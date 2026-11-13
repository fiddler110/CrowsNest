package dockerguard

import (
	"os"
	"slices"
	"strings"
	"testing"
)

const bareYAML = "games_root: /srv/games\nports: [\"27000-27999/udp\"]\n"

func TestResolveFillsImagesAndNetworkFromDefaults(t *testing.T) {
	p, err := ParsePolicy([]byte(bareYAML))
	if err != nil {
		t.Fatalf("a policy without images or networks was refused: %v", err)
	}
	d := Defaults{Images: []string{"lloesche/valheim-server", "thijsvanloef/palworld-server-docker"}, Network: "games-net"}
	if err := p.Resolve(d); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Images, "docker.io/lloesche/valheim-server") || len(p.Images) != 2 || !slices.Equal(p.Networks, []string{"games-net"}) {
		t.Errorf("images %v, networks %v", p.Images, p.Networks)
	}
	scope := mustScope(t, scopeJSON("any", "lloesche/valheim-server", `,"labels":{"`+OwnerLabel+`":"true"}`))
	scope.Networks = map[string]bool{"games-net": true}
	if err := p.Admit(scope); err != nil {
		t.Errorf("a module's image on the games network was refused: %v", err)
	}
	scope = mustScope(t, scopeJSON("any", "evil/miner", `,"labels":{"`+OwnerLabel+`":"true"}`))
	scope.Networks = map[string]bool{"games-net": true}
	if err := p.Admit(scope); err == nil || !strings.Contains(err.Error(), "images") {
		t.Errorf("an image no module declares was admitted: %v", err)
	}
}

// "@modules" plus an explicit entry is the way to add one image; an explicit list alone is exactly that list.
func TestResolveModulesTokenAndExplicitLists(t *testing.T) {
	d := Defaults{Images: []string{"lloesche/valheim-server"}, Network: "n"}
	p, _ := ParsePolicy([]byte(bareYAML + "images: [\"@modules\", \"ghcr.io/me/mygame\"]\nnetworks: [other]\n"))
	if err := p.Resolve(d); err != nil || !slices.Equal(p.Images, []string{"docker.io/lloesche/valheim-server", "ghcr.io/me/mygame"}) || !slices.Equal(p.Networks, []string{"other"}) {
		t.Errorf("%v %v %v", p.Images, p.Networks, err)
	}
	p, _ = ParsePolicy([]byte(bareYAML + "images: [\"ghcr.io/me/mygame\"]\n"))
	if err := p.Resolve(d); err != nil || len(p.Images) != 1 {
		t.Errorf("explicit list was widened: %v %v", p.Images, err)
	}
	// nothing to fall back on is an error, not an open door
	p, _ = ParsePolicy([]byte(bareYAML))
	if err := p.Resolve(Defaults{Network: "n"}); err == nil {
		t.Error("no images anywhere was accepted")
	}
	p, _ = ParsePolicy([]byte(bareYAML))
	if err := p.Resolve(Defaults{Images: d.Images}); err == nil {
		t.Error("no network anywhere was accepted")
	}
}

// An allowed module adds its bundled ports to the policy; an unknown id adds nothing.
func TestResolveAddsPortsOfAllowedModules(t *testing.T) {
	d := Defaults{Images: []string{"lloesche/valheim-server"}, Network: "n",
		ModulePorts: map[string][]string{"valheim": {"2456/udp", "2457/udp"}, "minecraft": {"25565/tcp"}},
		Allowed:     []string{"valheim", "not-a-module"}}
	p, err := ParsePolicy([]byte("games_root: /srv/games\n"))
	if err != nil {
		t.Fatalf("a policy with no ports was refused: %v", err)
	}
	if err := p.Resolve(d); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Ports, []string{"2456/udp", "2457/udp"}) {
		t.Errorf("ports %v, want only valheim's", p.Ports)
	}
}

func TestAllowedFileIsReadStrictly(t *testing.T) {
	dir := t.TempDir()
	f := dir + "/allowed.json"
	if got, err := ReadAllowed(f); err != nil || got != nil {
		t.Errorf("missing file: %v %v", got, err)
	}
	for body, ok := range map[string]bool{`{"modules":["valheim"]}`: true, ``: true, `{"modules":"all"}`: false, `{"everything":true}`: false, `nope`: false} {
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadAllowed(f); (err == nil) != ok {
			t.Errorf("%q: err %v, want ok=%v", body, err, ok)
		}
	}
	if AllowedPath("/x/managed/scopes.json") != "/x/managed/allowed.json" || AllowedPath("") != "" {
		t.Error("AllowedPath")
	}
}

func TestLoadPolicyDefaults_SignedModulesNeedTrustedKeys(t *testing.T) {
	write := func(extra string) string {
		f := t.TempDir() + "/policy.yaml"
		if err := os.WriteFile(f, []byte(bareYAML+extra), 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}
	called := 0
	signed := func(allowed []string, keys []PolicyKey) ([]string, map[string][]string, []error) {
		called++
		return []string{"example/mygame-server"}, map[string][]string{"mygame": {"7777/udp"}}, nil
	}
	d := Defaults{Images: []string{"lloesche/valheim-server"}, Network: "games-net", Allowed: []string{"mygame"}}

	// No trusted keys in the file: the hook is never asked, so the panel cannot talk its way in.
	p, _, err := LoadPolicyDefaults(write(""), d, signed)
	if err != nil || called != 0 || slices.Contains(p.Images, "docker.io/example/mygame-server") || p.PortAllowed("", "7777", "udp") {
		t.Fatalf("without keys: err=%v called=%d images=%v", err, called, p.Images)
	}
	// With a trusted key the module's image and port are admitted.
	p, _, err = LoadPolicyDefaults(write("trusted_keys:\n  - {name: me, public_key: AAAA}\n"), d, signed)
	if err != nil || called != 1 || !slices.Contains(p.Images, "docker.io/example/mygame-server") || !p.PortAllowed("", "7777", "udp") {
		t.Fatalf("with a key: err=%v called=%d images=%v", err, called, p.Images)
	}
	// A bundled module's compiled-in ports are never overridden by what the hook returns for the same id.
	d.ModulePorts = map[string][]string{"mygame": {"9999/udp"}}
	d.Allowed = []string{"mygame"}
	p, _, _ = LoadPolicyDefaults(write("trusted_keys:\n  - {name: me, public_key: AAAA}\n"), d, func([]string, []PolicyKey) ([]string, map[string][]string, []error) {
		return nil, nil, nil
	})
	if !p.PortAllowed("", "9999", "udp") {
		t.Error("compiled-in ports were lost")
	}
}
