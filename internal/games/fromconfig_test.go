package games

import (
	"testing"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
)

func TestFromConfig(t *testing.T) {
	cfgs := []config.GameConfig{
		{
			ID:             "windrose",
			DisplayName:    "Windrose",
			ContainerName:  "windrose",
			ComposeFile:    "/windrose/compose.yaml",
			ComposeProfile: "windrose",
			ComposeService: "windrose",
		},
		{
			ID:             "valheim",
			DisplayName:    "Valheim",
			ContainerName:  "valheim",
			ComposeFile:    "/valheim/compose.yaml",
			ComposeProfile: "valheim",
			ComposeService: "valheim",
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

	want := dockerctl.Target{
		ContainerName:  "valheim",
		ComposeFile:    "/valheim/compose.yaml",
		ComposeProfile: "valheim",
		ComposeService: "valheim",
	}
	if got := defs[1].DockerTarget(); got != want {
		t.Errorf("defs[1].DockerTarget() = %+v, want %+v", got, want)
	}
}
