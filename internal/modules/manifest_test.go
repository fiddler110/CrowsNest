package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
)

const good = `
api_version: 1
id: minecraft
name: Minecraft
runtime: {restart_cooldown: 20s}
startup:
  - {match: 'Preparing spawn', pct: 60, label: Spawn}
`

func TestParseAndWire(t *testing.T) {
	m, err := Parse(strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	def := &games.GameDef{ID: "minecraft"}
	m.Wire()(def, Env{})
	if def.RestartCooldown != 20*time.Second {
		t.Fatalf("cooldown %v", def.RestartCooldown)
	}
	if def.Startup == nil || len(def.Startup.Milestones) != 1 || def.Startup.Milestones[0].Pct != 60 {
		t.Fatalf("startup %+v", def.Startup)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"version":       "api_version: 2\nid: a\nname: A\n",
		"id":            "api_version: 1\nid: Bad_ID\nname: A\n",
		"name":          "api_version: 1\nid: a\n",
		"typo":          "api_version: 1\nid: a\nname: A\nrunetime: {}\n",
		"regex":         "api_version: 1\nid: a\nname: A\nstartup: [{match: '(', pct: 1}]\n",
		"pct":           "api_version: 1\nid: a\nname: A\nstartup: [{match: x, pct: 101}]\n",
		"players":       "api_version: 1\nid: a\nname: A\nplayers: {type: http_json}\n",
		"lm-incomplete": "api_version: 1\nid: a\nname: A\nplayers: {type: log_markers}\n",
		"lm-nogroup":    "api_version: 1\nid: a\nname: A\nstatus: {ready_log: ok}\nplayers: {type: log_markers, join: x, leave: 'y(.)'}\n",
		"negative":      "api_version: 1\nid: a\nname: A\nruntime: {restart_cooldown: -1s}\n",
	}
	for name, y := range cases {
		if _, err := Parse(strings.NewReader(y)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	write := func(d, y string) {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
		os.WriteFile(filepath.Join(dir, d, "module.yaml"), []byte(y), 0o644)
	}
	write("minecraft", good)
	s := Bundled()
	if err := s.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s.IDs(), ","); got != "minecraft,palworld,valheim,windrose" {
		t.Fatalf("ids %s", got)
	}
	if err := NewSet().LoadDir(filepath.Join(dir, "nope")); err != nil {
		t.Fatalf("missing dir: %v", err)
	}
	write("valheim", strings.ReplaceAll(good, "minecraft", "valheim"))
	if err := s.LoadDir(dir); err == nil {
		t.Fatal("expected duplicate error")
	}
	write("mismatch", good)
	if err := NewSet().LoadDir(dir); err == nil {
		t.Fatal("expected dir/id mismatch error")
	}
}

func TestLogMarkersWire(t *testing.T) {
	m, err := Parse(strings.NewReader(`
api_version: 1
id: valheim2
name: Valheim 2
status: {ready_log: 'Loading: Done\.'}
players: {type: log_markers, join: 'Got handshake from client (\S+)', leave: 'Closing socket (\S+)'}
`))
	if err != nil {
		t.Fatal(err)
	}
	def := &games.GameDef{ID: "valheim2", ContainerName: "valheim2"}
	runners := m.Wire()(def, Env{})
	if len(runners) != 1 || def.Status == nil || def.Players == nil || def.Info == nil {
		t.Fatalf("runners=%d def=%+v", len(runners), def)
	}
}
