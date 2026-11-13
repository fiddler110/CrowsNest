package games

import (
	"context"
	"testing"

	"github.com/fiddler110/crowsnest/internal/dockerctl/dockertest"
)

func TestDockerStatusChecker_Online(t *testing.T) {
	f := dockertest.New(t)
	f.Add("windrose", true)
	checker := &DockerStatusChecker{Docker: f.Client()}

	status, err := checker.Check(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if status != StatusOnline {
		t.Fatalf("Check() = %v, want %v", status, StatusOnline)
	}
}

func TestDockerStatusChecker_Offline(t *testing.T) {
	f := dockertest.New(t)
	f.Add("windrose", false)
	checker := &DockerStatusChecker{Docker: f.Client()}

	status, err := checker.Check(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if status != StatusOffline {
		t.Fatalf("Check() = %v, want %v", status, StatusOffline)
	}
}

func TestDockerStatusChecker_Error(t *testing.T) {
	f := dockertest.New(t)
	f.Down(true)
	checker := &DockerStatusChecker{Docker: f.Client()}

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
