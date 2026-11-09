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

func TestProbeWire(t *testing.T) {
	for _, y := range []string{
		"api_version: 1\nid: a\nname: A\nplayers: {type: http_json, url: 'http://x:1/p', count_path: players, name_field: name}\n",
		"api_version: 1\nid: a\nname: A\nplayers: {type: source_rcon, addr: 'x:27015', command: status, pattern: '^# \\d+ \"(.+?)\"'}\n",
	} {
		m, err := Parse(strings.NewReader(y))
		if err != nil {
			t.Fatal(err)
		}
		def := &games.GameDef{ID: "a"}
		m.Wire()(def, Env{})
		if def.Players == nil {
			t.Errorf("no players wired for %s", m.Players.Type)
		}
	}
}

func TestValheimStartup_RealLogLines(t *testing.T) {
	var def games.GameDef
	Bundled().wire["valheim"](&def, Env{})
	pct := func(line string) int {
		if p, _, ok := def.Startup.Parse(line); ok {
			return p
		}
		for _, m := range def.Startup.Milestones {
			if m.Pattern.MatchString(line) {
				return m.Pct
			}
		}
		return -1
	}
	for line, want := range map[string]int{
		"supervisord: valheim-updater INFO - Downloading/updating/validating Valheim server from Steam":            5,
		"supervisord: valheim-updater  Update state (0x61) downloading, progress: 50.00 (1093324632 / 2186649264)": 40,
		"supervisord: valheim-server 09/30/2026 09:46:41: Zonesystem Awake 5366":                                   72,
		"supervisord: valheim-server 09/30/2026 09:46:44: Load world: TestWorld (TestWorld)":                       80,
		"supervisord: valheim-server 09/30/2026 09:46:49: Loading: Generating locations":                           88,
		"supervisord: valheim-server 09/30/2026 09:47:12: Loading: Done. Total seconds sinze ZNet start: 27.97":    100,
		"supervisord: valheim-server The referenced script on this Behaviour is missing!":                          -1,
	} {
		if got := pct(line); got != want {
			t.Errorf("pct(%q) = %d, want %d", line, got, want)
		}
	}
}
