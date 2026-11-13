package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/vault"
)

func TestRekeyMovesEverythingAndCanBeRunAgain(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	managedDir := filepath.Join(root, "managed")
	for _, d := range []string{data, managedDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath := filepath.Join(root, "config.yaml")
	cfg := "server:\n  session_secret_file: " + data + "/session_secret\n  settings_file: " + data + "/settings.json\n  history_file: " + data + "/events.jsonl\n" +
		"users_file: " + data + "/users.env\nplatform:\n  games_root: /srv/games\nmanaged:\n  dir: " + managedDir + "\n  policy_file: " + root + "/policy.yaml\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CROWSNEST_CONFIG", cfgPath)
	const oldKey, newKey = "old-master-key-long-enough-xxxx", "new-master-key-long-enough-xxxx"
	t.Setenv(vault.EnvKey, oldKey)
	t.Setenv(NewKeyEnv, newKey)
	oldV, _ := vault.New(oldKey, "")
	newV, _ := vault.New(newKey, "")

	sealed, _ := oldV.Seal("managed:mc:RCON_PASSWORD", "hunter2")
	sec := filepath.Join(managedDir, "secrets.json")
	if err := os.WriteFile(sec, []byte(`{"mc":{"RCON_PASSWORD":"`+sealed+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	g, _ := oldV.Seal("google-client-secret", "gsecret")
	if err := os.WriteFile(filepath.Join(data, "auth.json"), []byte(`{"enabled":true,"client_id":"id","redirect_url":"https://x/cb","client_secret_enc":"`+g+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ss, _ := oldV.Seal("session-secret", "c2Vzc2lvbi1zZWNyZXQtc2Vzc2lvbi1zZWNyZXQtMTIzNDU2")
	if err := os.WriteFile(filepath.Join(data, "session_secret"), []byte(ss+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runRekey(&out); err != nil {
		t.Fatalf("rekey: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "3 values moved") {
		t.Errorf("output = %s", out.String())
	}
	b, _ := os.ReadFile(sec)
	if strings.Contains(string(b), oldKey) || !strings.Contains(string(b), "enc:v2:") {
		t.Fatalf("secrets.json = %s", b)
	}
	if got, _, err := newV.Unseal("managed:mc:RCON_PASSWORD", extract(string(b))); err != nil || got != "hunter2" {
		t.Fatalf("new key opens the secret: %q %v", got, err)
	}
	if _, _, err := oldV.Unseal("managed:mc:RCON_PASSWORD", extract(string(b))); err == nil {
		t.Error("old key still opens it")
	}
	// Run again (as after an interruption): nothing changes, nothing fails.
	out.Reset()
	if err := runRekey(&out); err != nil || !strings.Contains(out.String(), "0 values moved") {
		t.Fatalf("second run: %v\n%s", err, out.String())
	}

	// A wrong current key stops with an error and leaves the file as it was.
	t.Setenv(vault.EnvKey, "some-other-master-key-long-enough")
	orig := []byte(`{"mc":{"RCON_PASSWORD":"` + sealed + `"}}`)
	if err := os.WriteFile(sec, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runRekey(&out); err == nil {
		t.Fatal("rekey with the wrong current key succeeded")
	}
	if after, _ := os.ReadFile(sec); !bytes.Equal(after, orig) {
		t.Fatalf("a failed rekey changed secrets.json: %s", after)
	}
}

// extract pulls the one sealed value out of a secrets.json body.
func extract(body string) string {
	i := strings.Index(body, "enc:v")
	j := strings.Index(body[i:], `"`)
	return body[i : i+j]
}
