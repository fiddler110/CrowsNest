package games

import (
	"testing"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
)

func TestFromConfig_ConnectSecrets(t *testing.T) {
	t.Setenv("TEST_JOIN_PASS", "hunter2")
	t.Setenv("TEST_EMPTY", "")
	defs := FromConfig([]config.GameConfig{{
		ID: "g", DisplayName: "G", ContainerName: "g",
		ConnectSecrets: []config.ConnectSecret{
			{Label: "Join password", Env: "TEST_JOIN_PASS"},
			{Label: "Empty", Env: "TEST_EMPTY"},
			{Label: "Unset", Env: "TEST_DEFINITELY_UNSET"},
		},
	}}, &dockerctl.Client{})
	got := defs[0].ConnectSecrets
	if len(got) != 1 || got[0].Label != "Join password" || got[0].Value != "hunter2" {
		t.Errorf("ConnectSecrets = %+v, want only the set variable", got)
	}
}

func TestFromConfig(t *testing.T) {
	optedOut := false
	cfgs := []config.GameConfig{
		{
			ID:             "windrose",
			DisplayName:    "Windrose",
			ContainerName:  "windrose",
			ConnectAddress: "play.example.com:8211",
			ConnectNote:    "Ask for the password",
		},
		{
			ID:            "valheim",
			DisplayName:   "Valheim",
			ContainerName: "valheim",
			NightShutdown: &optedOut,
		},
	}
	docker := &dockerctl.Client{}

	defs := FromConfig(cfgs, docker)
	if len(defs) != 2 {
		t.Fatalf("len(FromConfig()) = %d, want 2", len(defs))
	}

	d := defs[0]
	if d.ID != "windrose" || d.DisplayName != "Windrose" || d.ContainerName != "windrose" {
		t.Fatalf("defs[0] = %+v", d)
	}
	if _, ok := d.Status.(*DockerStatusChecker); !ok {
		t.Errorf("defs[0].Status = %T, want *DockerStatusChecker", d.Status)
	}
	if _, ok := d.Players.(UnknownPlayerCounter); !ok {
		t.Errorf("defs[0].Players = %T, want UnknownPlayerCounter", d.Players)
	}
	if d.ConnectAddress != "play.example.com:8211" || d.ConnectNote != "Ask for the password" {
		t.Errorf("defs[0] connect = %q / %q", d.ConnectAddress, d.ConnectNote)
	}
	if defs[1].ConnectAddress != "" || defs[1].ConnectNote != "" {
		t.Errorf("defs[1] connect = %q / %q, want empty", defs[1].ConnectAddress, defs[1].ConnectNote)
	}
	if !d.NightShutdown {
		t.Errorf("defs[0].NightShutdown = false, want true (included by default)")
	}
	if defs[1].NightShutdown {
		t.Errorf("defs[1].NightShutdown = true, want false (explicitly opted out)")
	}

	want := dockerctl.Target{ContainerName: "valheim"}
	if got := defs[1].DockerTarget(); got != want {
		t.Errorf("defs[1].DockerTarget() = %+v, want %+v", got, want)
	}
}
