package main

import (
	"testing"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerguard"
)

// The quickstart's config and policy are what a stranger copies first, so they
// must keep loading and must agree on where game data lives.
func TestQuickstartConfigAndPolicy(t *testing.T) {
	cfg, err := config.Load("../../quickstart/config.yaml")
	if err != nil {
		t.Fatalf("quickstart/config.yaml: %v", err)
	}
	if cfg.Managed.Dir == "" || len(cfg.Games) != 0 {
		t.Fatalf("quickstart should enable dashboard games and define none: %+v", cfg.Managed)
	}
	pol, err := dockerguard.LoadPolicy("../../quickstart/policy/policy.yaml")
	if err != nil {
		t.Fatalf("quickstart/policy/policy.yaml: %v", err)
	}
	if pol.GamesRoot != cfg.Platform.GamesRoot {
		t.Fatalf("games_root differs: policy %q, config %q", pol.GamesRoot, cfg.Platform.GamesRoot)
	}
}
