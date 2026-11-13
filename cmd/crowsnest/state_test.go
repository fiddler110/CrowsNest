package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/config"
)

func stateConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	root := t.TempDir()
	cfg := &config.Config{UsersFile: filepath.Join(root, "users"), ModulesDir: filepath.Join(root, "modules")}
	cfg.Server.SettingsFile = filepath.Join(root, "data", "settings.json")
	cfg.Server.HistoryFile = filepath.Join(root, "data", "events.jsonl")
	cfg.Managed.Dir = filepath.Join(root, "managed")
	return cfg, root
}

func writeAll(t *testing.T, files map[string]string) {
	t.Helper()
	for p, c := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStateExportRestoreRoundTrip(t *testing.T) {
	cfg, root := stateConfig(t)
	files := map[string]string{
		cfg.UsersFile:                                          "ALEX_HASH=x\n",
		cfg.Server.SettingsFile:                                `{"idle":1}`,
		cfg.Server.HistoryFile:                                 "{}\n",
		filepath.Join(root, "data", "mfa.json"):                "sealed-mfa",
		filepath.Join(cfg.Managed.Dir, "secrets.json"):         "sealed-secrets",
		filepath.Join(cfg.ModulesDir, "modules.lock.json"):     "{}",
		filepath.Join(cfg.ModulesDir, "mygame", "module.yaml"): "id: mygame\n",
		// Must never be exported.
		filepath.Join(root, "data", "master.key"):          "VAULT-KEY",
		filepath.Join(root, "data", "session-secret"):      "SESSION",
		filepath.Join(root, "data", "sessions.json"):       "{}",
		filepath.Join(cfg.ModulesDir, "handmade", "x.txt"): "not state",
	}
	writeAll(t, files)
	var buf bytes.Buffer
	names, err := stateExport(cfg, &buf)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"users/users", "settings/settings.json", "settings/mfa.json", "history/events.jsonl",
		"managed/secrets.json", "modules/modules.lock.json", "modules/mygame/module.yaml"} {
		if !strings.Contains(joined, want) {
			t.Errorf("snapshot lacks %s: %s", want, joined)
		}
	}
	for _, bad := range []string{"master.key", "session-secret", "sessions.json", "x.txt"} {
		if strings.Contains(joined, bad) {
			t.Errorf("snapshot holds %s", bad)
		}
	}
	if strings.Contains(buf.String(), "VAULT-KEY") {
		t.Error("vault key bytes in the snapshot")
	}

	// Restoring onto existing files is refused without --force, and changes nothing.
	snap := buf.Bytes()
	if err := stateRestore(cfg, bytes.NewReader(snap), false, io.Discard); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("restore over existing files = %v", err)
	}
	// Wipe and restore.
	for _, p := range []string{cfg.UsersFile, cfg.Server.SettingsFile, filepath.Join(cfg.ModulesDir, "mygame", "module.yaml")} {
		_ = os.Remove(p)
	}
	if err := stateRestore(cfg, bytes.NewReader(snap), true, io.Discard); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{cfg.UsersFile: files[cfg.UsersFile], cfg.Server.SettingsFile: `{"idle":1}`,
		filepath.Join(cfg.ModulesDir, "mygame", "module.yaml"): "id: mygame\n"} {
		if got, _ := os.ReadFile(p); string(got) != want {
			t.Errorf("%s = %q, want %q", p, got, want)
		}
	}
}

func TestStateRestoreRefusesForeignNames(t *testing.T) {
	cfg, root := stateConfig(t)
	for _, name := range []string{"../evil", "users/../../evil", "/etc/passwd", "settings/master.key", "modules/../x", "other/file", "modules/UP/module.yaml"} {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: 1})
		_, _ = tw.Write([]byte("x"))
		tw.Close()
		gz.Close()
		if err := stateRestore(cfg, &buf, true, io.Discard); err == nil {
			t.Errorf("%q was accepted", name)
		}
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Errorf("a refused snapshot wrote files: %v", entries)
	}
}
