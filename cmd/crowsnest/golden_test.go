package main

// Characterization ("golden") tests for the three production games.
//
// They pin what CrowsNest does today for the lab's real config: which
// strategies each game gets, which exec commands are allowlisted, and which
// scopes the Docker API guard enforces. The modular rework (docs/modularization-plan.md)
// must keep every one of these identical until a change is deliberate; when it
// is, regenerate with
//
//	go test ./cmd/crowsnest -run Golden -update
//
// and review the diff of testdata/*.golden.json.
//
// testdata/prod/config.yaml is a copy of the production config, domain replaced (it
// holds environment-variable NAMES only, never secrets); guard_scopes.json is
// the production GUARD_SCOPES with ${USERDIR} made literal.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/dockerguard"
	"github.com/fiddler110/crowsnest/internal/games"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func loadProdConfig(t *testing.T) *config.Config {
	t.Helper()
	// Values only need to be non-empty so secret-bearing wiring is exercised.
	for _, e := range []string{
		"PALWORLD_ADMIN_PASSWORD", "WINDROSE_RCON_PASSWORD", "PALWORLD_SERVER_PASSWORD",
		"VALHEIM_SERVER_NAME", "VALHEIM_WORLD_NAME", "VALHEIM_SERVER_PASS",
		"WINDROSE_INVITE_CODE", "WINDROSE_SERVER_NAME", "WINDROSE_SERVER_PASSWORD",
	} {
		t.Setenv(e, "test-"+e)
	}
	t.Setenv(config.MaxActiveGamesEnv, "")
	cfg, err := config.Load(filepath.Join("testdata", "prod", "config.yaml"))
	if err != nil {
		t.Fatalf("production config no longer loads: %v", err)
	}
	return cfg
}

// golden compares got (as indented JSON) with testdata/<name>.golden.json.
func golden(t *testing.T, name string, got any) {
	t.Helper()
	b, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	path := filepath.Join("testdata", name+".golden.json")
	if *update {
		if err := os.WriteFile(path, b, 0o644); err != nil { // #nosec G306 -- test fixture
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) // #nosec G304 -- fixed test path
	if err != nil {
		t.Fatalf("%v (create it with -update)", err)
	}
	if string(want) != string(b) {
		t.Errorf("%s changed; if intended, run with -update and review the diff.\n--- want\n%s\n--- got\n%s", path, want, b)
	}
}

func TestGoldenExecRules(t *testing.T) {
	type rule struct {
		Container string
		Cmd       []string
	}
	var got []rule
	for _, r := range execRules(loadProdConfig(t)) {
		got = append(got, rule{r.Container, r.Cmd})
	}
	golden(t, "exec_rules", got)
}

func TestGoldenGuardScopes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "prod", "guard_scopes.json"))
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := dockerguard.LoadScopes(string(raw))
	if err != nil {
		t.Fatalf("production GUARD_SCOPES no longer parses: %v", err)
	}
	golden(t, "guard_scopes", scopes)
}

// wiring describes a GameDef by what is attached to it, not by pointer
// values, so it is stable across runs.
type wiring struct {
	ID              string
	DisplayName     string
	Container       string
	ComposeProfile  string
	ComposeService  string
	Status          string
	Players         string
	Info            string
	PreStop         string
	Console         string
	RawConsole      string
	StartupSteps    int
	StartupParse    bool
	RestartCooldown string
	NightShutdown   bool
	ConnectAddress  string
	ConnectNote     string
	ConnectSecrets  []string
	Backup          *games.BackupSpec
	CanCountPlayers bool
}

func typeName(v any) string {
	if v == nil || (reflect.ValueOf(v).Kind() == reflect.Pointer && reflect.ValueOf(v).IsNil()) {
		return ""
	}
	return fmt.Sprintf("%T", v)
}

func TestGoldenGameWiring(t *testing.T) {
	cfg := loadProdConfig(t)
	defs, tr := buildGameDefs(cfg, &dockerctl.Client{})
	if len(tr.valheim) != 1 || len(tr.windrose) != 1 {
		t.Errorf("trackers: valheim=%d windrose=%d, want 1 each", len(tr.valheim), len(tr.windrose))
	}
	var got []wiring
	for _, d := range defs {
		w := wiring{
			ID: d.ID, DisplayName: d.DisplayName, Container: d.ContainerName,
			ComposeProfile: d.ComposeProfile, ComposeService: d.ComposeService,
			Status: typeName(d.Status), Players: typeName(d.Players), Info: typeName(d.Info),
			PreStop: typeName(d.PreStop), Console: typeName(d.Console), RawConsole: typeName(d.RawConsole),
			RestartCooldown: d.RestartCooldown.String(), NightShutdown: d.NightShutdown,
			ConnectAddress: d.ConnectAddress, ConnectNote: d.ConnectNote,
			Backup: d.Backup, CanCountPlayers: games.CanCountPlayers(d),
		}
		if d.Startup != nil {
			w.StartupSteps = len(d.Startup.Milestones)
			w.StartupParse = d.Startup.Parse != nil
		}
		for _, s := range d.ConnectSecrets {
			w.ConnectSecrets = append(w.ConnectSecrets, s.Label) // labels only: values are secrets
		}
		got = append(got, w)
	}
	golden(t, "game_wiring", got)
}

// TestGuardMatchesConfig is the invariant that today is only enforced by hand:
// every configured game has a guard scope of the same name, and every game
// with a backup (an exec rule) has exec enabled in its scope. Once scopes are
// derived from module manifests this holds by construction and the test stays
// as a regression guard.
func TestGuardMatchesConfig(t *testing.T) {
	cfg := loadProdConfig(t)
	raw, err := os.ReadFile(filepath.Join("testdata", "prod", "guard_scopes.json"))
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := dockerguard.LoadScopes(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*dockerguard.Scope{}
	for _, s := range scopes {
		byName[s.Name] = s
	}
	var names []string
	for _, g := range cfg.Games {
		names = append(names, g.ContainerName)
		s, ok := byName[g.ContainerName]
		if !ok {
			t.Errorf("game %s: no guard scope named %q", g.ID, g.ContainerName)
			continue
		}
		if g.Backup != nil && !s.Exec {
			t.Errorf("game %s has a backup but scope %q does not allow exec", g.ID, s.Name)
		}
	}
	sort.Strings(names)
	for name := range byName {
		if i := sort.SearchStrings(names, name); i == len(names) || names[i] != name {
			t.Errorf("guard scope %q has no configured game", name)
		}
	}
}
