package games

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
)

func fakeDockerClient(t *testing.T, script string) *dockerctl.Client {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "docker")
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	return &dockerctl.Client{DockerBin: binPath}
}

func TestDockerStatusChecker_Online(t *testing.T) {
	docker := fakeDockerClient(t, "#!/bin/sh\n[ \"$1\" = ps ] && echo windrose\n")
	checker := &DockerStatusChecker{Docker: docker}

	status, err := checker.Check(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if status != StatusOnline {
		t.Fatalf("Check() = %v, want %v", status, StatusOnline)
	}
}

func TestDockerStatusChecker_Offline(t *testing.T) {
	docker := fakeDockerClient(t, "#!/bin/sh\n[ \"$1\" = ps ] && :\n")
	checker := &DockerStatusChecker{Docker: docker}

	status, err := checker.Check(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if status != StatusOffline {
		t.Fatalf("Check() = %v, want %v", status, StatusOffline)
	}
}

func TestDockerStatusChecker_Error(t *testing.T) {
	docker := fakeDockerClient(t, "#!/bin/sh\necho boom >&2\nexit 1\n")
	checker := &DockerStatusChecker{Docker: docker}

	if _, err := checker.Check(context.Background(), "windrose"); err == nil {
		t.Fatal("Check() error = nil, want error")
	}
}

func TestUnknownPlayerCounter(t *testing.T) {
	count, names, ok := UnknownPlayerCounter{}.PlayerCount(context.Background())
	if ok {
		t.Fatal("PlayerCount() ok = true, want false (undetermined)")
	}
	if count != 0 || names != nil {
		t.Fatalf("PlayerCount() = (%d, %v), want (0, nil) when ok=false", count, names)
	}
}
