package main

import (
	"os"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

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

// The panel must be pointed at the guard's container name, and the guard must run
// the exec allowlist itself, since the quickstart has no separate execguard.
func TestQuickstartComposeIsPanelPlusGuard(t *testing.T) {
	cfg, err := config.Load("../../quickstart/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../quickstart/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Services map[string]struct {
			ContainerName string   `yaml:"container_name"`
			Command       []string `yaml:"command"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Services) != 2 {
		t.Errorf("want the panel and the guard only, got %d services", len(c.Services))
	}
	g := c.Services["guard"]
	if want := "tcp://" + g.ContainerName + ":2375"; cfg.Server.DockerHost != want {
		t.Errorf("docker_host = %q, want %q", cfg.Server.DockerHost, want)
	}
	if !slices.Contains(g.Command, "--exec") {
		t.Errorf("the guard does not run the exec allowlist: %v", g.Command)
	}
}
