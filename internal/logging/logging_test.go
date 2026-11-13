package logging

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
)

func TestJSONAndLevelFilteringReachStdlibLog(t *testing.T) {
	var buf bytes.Buffer
	if err := Setup(&buf, "warn", "json"); err != nil {
		t.Fatal(err)
	}
	log.Printf("games: loaded 3")
	log.Printf("docker: ping failed: boom")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want only the warning, got %q", buf.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil || m["level"] != "WARN" || m["msg"] != "docker: ping failed: boom" {
		t.Errorf("line = %v (%v)", m, err)
	}
}

func TestBadSettingsAreRefused(t *testing.T) {
	if Setup(&bytes.Buffer{}, "loud", "text") == nil || Setup(&bytes.Buffer{}, "info", "xml") == nil {
		t.Error("accepted a bad level or format")
	}
}
