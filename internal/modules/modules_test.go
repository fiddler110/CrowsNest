package modules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

type fakeRunner struct{}

func (fakeRunner) Run(context.Context) {}

func TestBuildWiresRegisteredAndKeepsBaselineForUnknown(t *testing.T) {
	s := NewSet()
	s.Register("known", func(def *games.GameDef, env Env) []Runner {
		def.RestartCooldown = 5
		if env.Config.ID != "known" {
			t.Errorf("env.Config.ID = %q, want known", env.Config.ID)
		}
		return []Runner{fakeRunner{}}
	})
	cfg := &config.Config{Games: []config.GameConfig{{ID: "other"}, {ID: "known"}}}
	defs, runners := s.Build(cfg, &dockerctl.Client{})

	if len(defs) != 2 || defs[0].ID != "other" || defs[1].ID != "known" {
		t.Fatalf("defs out of config order: %+v", defs)
	}
	if defs[1].RestartCooldown != 5 || defs[0].RestartCooldown != 0 {
		t.Errorf("cooldowns = %v/%v, want 0/5", defs[0].RestartCooldown, defs[1].RestartCooldown)
	}
	if defs[0].Status == nil || defs[0].Players == nil {
		t.Error("a game with no module should keep the baseline status and player counter")
	}
	if len(runners) != 1 {
		t.Errorf("runners = %d, want 1", len(runners))
	}
}

func TestRegisterRejectsDuplicateAndEmpty(t *testing.T) {
	noop := func(*games.GameDef, Env) []Runner { return nil }
	for name, fn := range map[string]func(){
		"duplicate": func() { s := NewSet(); s.Register("a", noop); s.Register("a", noop) },
		"empty id":  func() { NewSet().Register("", noop) },
		"nil func":  func() { NewSet().Register("a", nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: want panic", name)
				}
			}()
			fn()
		}()
	}
}

func TestBundledIDs(t *testing.T) {
	want := []string{"palworld", "valheim", "windrose"}
	if got := Bundled().IDs(); !reflect.DeepEqual(got, want) {
		t.Errorf("Bundled IDs = %v, want %v", got, want)
	}
}

func TestForConfig_LocalModuleDrivesConfiguredGame(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "minecraft"), 0o755); err != nil {
		t.Fatal(err)
	}
	y := "api_version: 1\nid: minecraft\nname: Minecraft\nruntime: {restart_cooldown: 20s}\nstartup:\n  - {match: Done, pct: 100, label: Ready}\n"
	if err := os.WriteFile(filepath.Join(dir, "minecraft", "module.yaml"), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "orphan"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "orphan", "module.yaml"), []byte("api_version: 1\nid: orphan\nname: Orphan\n"), 0o644)

	cfg := &config.Config{ModulesDir: dir, Games: []config.GameConfig{
		{ID: "minecraft", DisplayName: "Minecraft", ContainerName: "minecraft"},
		{ID: "valheim", DisplayName: "Valheim", ContainerName: "valheim"},
	}}
	var warned []string
	set, err := ForConfig(cfg, func(f string, a ...any) { warned = append(warned, fmt.Sprintf(f, a...)) })
	if err != nil {
		t.Fatal(err)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "orphan") {
		t.Fatalf("warnings %v", warned)
	}
	defs, _ := set.Build(cfg, &dockerctl.Client{})
	if defs[0].RestartCooldown != 20*time.Second || defs[0].Startup == nil {
		t.Fatalf("minecraft not wired from module.yaml: %+v", defs[0])
	}
	if defs[1].Players == nil { // legacy bundled path still wires valheim
		t.Fatal("valheim lost its bundled wiring")
	}

	// A local module may not shadow a bundled one.
	os.MkdirAll(filepath.Join(dir, "valheim"), 0o755)
	os.WriteFile(filepath.Join(dir, "valheim", "module.yaml"), []byte("api_version: 1\nid: valheim\nname: V\n"), 0o644)
	if _, err := ForConfig(cfg, nil); err == nil {
		t.Fatal("expected error for shadowing a bundled module")
	}
}

func TestForConfig_NoDirIsBundledOnly(t *testing.T) {
	set, err := ForConfig(&config.Config{}, nil)
	if err != nil || len(set.IDs()) != 3 {
		t.Fatalf("%v %v", set.IDs(), err)
	}
}
