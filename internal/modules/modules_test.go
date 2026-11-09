package modules

import (
	"context"
	"reflect"
	"testing"

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
