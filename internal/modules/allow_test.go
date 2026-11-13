package modules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fiddler110/crowsnest/internal/dockerguard"
)

func signedModuleDir(t *testing.T, id string, mutate func(body []byte) []byte) (dir string, keys []dockerguard.PolicyKey, body []byte) {
	t.Helper()
	b, err := os.ReadFile("../../docs/examples/mygame/module.yaml")
	if err != nil {
		t.Fatal(err)
	}
	seed, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(seed, b)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		b = mutate(b) // changed after signing
	}
	dir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, id), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id, "module.yaml"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SaveSignature(dir, id, sig); err != nil {
		t.Fatal(err)
	}
	return dir, []dockerguard.PolicyKey{{Name: "me", PublicKey: pub}}, b
}

func TestSignedAllowances(t *testing.T) {
	dir, keys, _ := signedModuleDir(t, "mygame", nil)
	imgs, ports, problems := SignedAllowances(dir, []string{"mygame"}, keys)
	if len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	if len(imgs) != 1 || imgs[0] != "docker.io/example/mygame-server" || len(ports["mygame"]) == 0 {
		t.Fatalf("images %v ports %v", imgs, ports)
	}
}

func TestSignedAllowances_RefusesWhatItCannotVouchFor(t *testing.T) {
	dir, keys, _ := signedModuleDir(t, "mygame", nil)
	_, otherPub, _ := GenerateKey()
	other := []dockerguard.PolicyKey{{Name: "x", PublicKey: otherPub}}

	cases := map[string]func() (string, []dockerguard.PolicyKey, []string){
		"a key the operator does not trust": func() (string, []dockerguard.PolicyKey, []string) { return dir, other, []string{"mygame"} },
		"no keys at all":                    func() (string, []dockerguard.PolicyKey, []string) { return dir, nil, []string{"mygame"} },
		"no modules folder":                 func() (string, []dockerguard.PolicyKey, []string) { return "", keys, []string{"mygame"} },
		"a module that is not there":        func() (string, []dockerguard.PolicyKey, []string) { return dir, keys, []string{"absent"} },
		"an id that climbs out":             func() (string, []dockerguard.PolicyKey, []string) { return dir, keys, []string{"../mygame"} },
		"a body changed after signing": func() (string, []dockerguard.PolicyKey, []string) {
			d, k, _ := signedModuleDir(t, "mygame", func(b []byte) []byte { return append(b, []byte("\n# edited\n")...) })
			return d, k, []string{"mygame"}
		},
		"a signed module filed under another id": func() (string, []dockerguard.PolicyKey, []string) {
			d, k, _ := signedModuleDir(t, "othergame", nil)
			return d, k, []string{"othergame"}
		},
	}
	for name, c := range cases {
		d, k, ids := c()
		imgs, ports, problems := SignedAllowances(d, ids, k)
		if len(problems) == 0 || len(imgs) != 0 || len(ports) != 0 {
			t.Errorf("%s: imgs=%v ports=%v problems=%v", name, imgs, ports, problems)
		}
	}
	// A hash-pinned install keeps no signature, so it never counts.
	if err := SaveSignature(dir, "mygame", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, problems := SignedAllowances(dir, []string{"mygame"}, keys); len(problems) == 0 {
		t.Error("a module with no saved signature was admitted")
	}
}

func TestSignedAllowances_BundledIsLeftToTheCompiledPorts(t *testing.T) {
	dir, keys, _ := signedModuleDir(t, "mygame", nil)
	imgs, ports, problems := SignedAllowances(dir, []string{"valheim"}, keys)
	if len(imgs)+len(ports)+len(problems) != 0 {
		t.Fatalf("bundled id produced %v %v %v", imgs, ports, problems)
	}
}
