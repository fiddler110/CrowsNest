package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/vault"
)

func TestGoogleConfStore(t *testing.T) {
	dir := t.TempDir()
	path, key := filepath.Join(dir, "auth.json"), filepath.Join(dir, "master.key")
	vlt, err := vault.New("", key)
	if err != nil {
		t.Fatal(err)
	}
	fb := GoogleSettings{Enabled: true, ClientID: "env-id", ClientSecret: "env-secret", RedirectURL: "https://x.example/auth/google/callback"}
	s, err := NewGoogleConfStore(path, vlt, fb)
	if err != nil {
		t.Fatal(err)
	}
	if v, src := s.Effective(); src != GoogleSourceEnvironment || v.ClientID != "env-id" {
		t.Fatalf("before save: %+v from %s", v, src)
	}
	want := GoogleSettings{Enabled: true, ClientID: "id", ClientSecret: "s3cret-value", RedirectURL: "https://c.example/auth/google/callback"}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "s3cret-value") {
		t.Fatal("client secret is stored in plain text")
	}
	s2, err := NewGoogleConfStore(path, vlt, fb)
	if err != nil {
		t.Fatal(err)
	}
	if v, src := s2.Effective(); src != GoogleSourceDashboard || v != want {
		t.Fatalf("after reload: %+v from %s", v, src)
	}
	// A different key can't read it.
	other, _ := vault.New("another-long-master-key-value-xx", "")
	if st, err := NewGoogleConfStore(path, other, fb); err == nil || st == nil {
		t.Fatalf("replaced key: store %v, err %v; want a usable store and an error", st, err)
	}
	if err := s2.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, src := s2.Effective(); src != GoogleSourceEnvironment {
		t.Fatalf("after clear: %s", src)
	}
}

func TestGoogleSettingsValidate(t *testing.T) {
	ok := GoogleSettings{Enabled: true, ClientID: "a", ClientSecret: "b", RedirectURL: "https://h.example/auth/google/callback"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*GoogleSettings){
		"no secret":   func(g *GoogleSettings) { g.ClientSecret = "" },
		"http host":   func(g *GoogleSettings) { g.RedirectURL = "http://h.example/auth/google/callback" },
		"wrong path":  func(g *GoogleSettings) { g.RedirectURL = "https://h.example/cb" },
		"query":       func(g *GoogleSettings) { g.RedirectURL = "https://h.example/auth/google/callback?x=1" },
		"space in id": func(g *GoogleSettings) { g.ClientID = "a b" },
	} {
		g := ok
		mod(&g)
		if g.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	local := ok
	local.RedirectURL = "http://localhost:8080/auth/google/callback"
	if err := local.Validate(); err != nil {
		t.Errorf("localhost http: %v", err)
	}
}
