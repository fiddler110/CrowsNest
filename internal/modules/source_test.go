package modules

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/probes"
)

// sections splits testdata/source_status.txt ("== name ==" headers).
func sections(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("testdata/source_status.txt")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	var name string
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if strings.HasPrefix(l, "== ") {
			name = strings.Trim(strings.TrimSpace(l), "= ")
			continue
		}
		out[name] += l
	}
	return out
}

func sourceDef(t *testing.T, opts map[string]string) *games.GameDef {
	t.Helper()
	var def games.GameDef
	Bundled().wire["source"](&def, Env{Config: config.GameConfig{ID: "tf2", Options: opts}})
	return &def
}

func TestSourceStatusFormats(t *testing.T) {
	want := map[string][]string{
		"tf2":  {"Alex", "Sam Smith"}, // the BOT is not a player
		"l4d2": {"Alex"},
		"cs2":  {"Alex"},
	}
	for game, names := range want {
		def := sourceDef(t, map[string]string{"rcon_addr": "g:27015", "rcon_password_env": "X"})
		p, ok := def.Players.(*probes.SourceRCON)
		if !ok {
			t.Fatalf("%s: Players = %T, want *probes.SourceRCON", game, def.Players)
		}
		reply := sections(t)[game]
		p.Exec = func(_ context.Context, addr, _, cmd string, _ time.Duration) (string, error) {
			if addr != "g:27015" || cmd != "status" {
				t.Errorf("rcon addr/cmd = %q %q", addr, cmd)
			}
			return reply, nil
		}
		n, got, ok := p.PlayerCount(context.Background())
		if !ok || n != len(names) || !reflect.DeepEqual(got, names) {
			t.Errorf("%s: %d %v, want %v", game, n, got, names)
		}
	}
}

func TestSourceNeedsRconAddr(t *testing.T) {
	def := sourceDef(t, nil)
	if def.Players != nil {
		t.Errorf("Players = %T without rcon_addr, want baseline (nil)", def.Players)
	}
	if def.RawConsole != nil {
		t.Error("RawConsole wired without rcon_addr")
	}
	if def := sourceDef(t, map[string]string{"rcon_addr": "g:27015"}); def.RawConsole == nil {
		t.Error("raw console not wired when rcon_addr is set")
	}
}

func TestSourceStartupLines(t *testing.T) {
	def := sourceDef(t, nil)
	for line, min := range map[string]int{
		"Update state (0x61) downloading, progress: 50.0 (1 / 2)": 30,
		"Success! App '232250' fully installed.":                  75,
		"Connection to Steam servers successful.":                 100,
	} {
		pct, ok := startupPct(def.Startup, line)
		if !ok || pct < min {
			t.Errorf("%q -> %d %v, want >= %d", line, pct, ok, min)
		}
	}
}

// One module, several games: "module: source" routes a game whose id has no
// module of its own, and an unknown module name keeps the baseline.
func TestModuleKeySelectsSharedModule(t *testing.T) {
	cfg := &config.Config{Games: []config.GameConfig{
		{ID: "tf2", ContainerName: "tf2", Module: "source", Options: map[string]string{"rcon_addr": "tf2:27015"}},
		{ID: "cs2", ContainerName: "cs2", Module: "source", Options: map[string]string{"rcon_addr": "cs2:27015"}},
		{ID: "ghost", ContainerName: "ghost", Module: "nope"},
	}}
	defs, _ := Bundled().Build(cfg, nil)
	for _, i := range []int{0, 1} {
		p, ok := defs[i].Players.(*probes.SourceRCON)
		if !ok || p.Addr != cfg.Games[i].Options["rcon_addr"] {
			t.Errorf("%s: Players = %#v", defs[i].ID, defs[i].Players)
		}
	}
	if defs[2].Startup != nil {
		t.Error("unknown module changed the baseline")
	}
}

func TestDontStarveSession(t *testing.T) {
	b, err := os.ReadFile("testdata/dontstarve_session.log")
	if err != nil {
		t.Fatal(err)
	}
	tr := trackerFor(t, "dontstarve")
	peak, last := 0, -1
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		tr.Replay(strings.NewReader(l))
		n, _, _ := tr.PlayerCount(context.Background())
		if n > peak {
			peak = n
		}
		last = n
	}
	if !tr.Ready() {
		t.Error("ready marker not recognised")
	}
	if peak != 2 { // a chat line quoting the announcement must not count
		t.Errorf("peak = %d, want 2", peak)
	}
	if last != 0 {
		t.Errorf("after both left = %d, want 0", last)
	}
}

// startupPct mirrors how the startup stream reads a line: Parse first, then
// the first milestone that matches.
func startupPct(sm *games.StartupMatcher, line string) (int, bool) {
	if sm.Parse != nil {
		if pct, _, ok := sm.Parse(line); ok {
			return pct, true
		}
	}
	for _, m := range sm.Milestones {
		if m.Pattern.MatchString(line) {
			return m.Pct, true
		}
	}
	return 0, false
}
