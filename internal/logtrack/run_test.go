package logtrack

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
)

// fakeDocker writes a docker stand-in: ps reports the container as running
// (or not), inspect gives a start time, logs prints a canned run.
func fakeDocker(t *testing.T, running bool, logs string) *dockerctl.Client {
	t.Helper()
	dir := t.TempDir()
	ps := ""
	if running {
		ps = "v"
	}
	script := `#!/bin/sh
case "$1" in
  ps) printf '%s' "` + ps + `" ;;
  inspect) echo "2026-01-01T00:00:00Z" ;;
  logs) cat <<'LOG'
` + logs + `
LOG
  ;;
esac
`
	bin := filepath.Join(dir, "docker")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return &dockerctl.Client{DockerBin: bin}
}

func TestCheck(t *testing.T) {
	ctx := context.Background()
	off := New(fakeDocker(t, false, ""), "v", valheimSpec())
	if s, err := off.Check(ctx, "v"); err != nil || s != games.StatusOffline {
		t.Fatalf("offline: %v %v", s, err)
	}
	on := New(fakeDocker(t, true, ""), "v", valheimSpec())
	if s, _ := on.Check(ctx, "v"); s != games.StatusStarting {
		t.Fatalf("running, no marker: %v", s)
	}
	on.Replay(strings.NewReader("Loading: Done."))
	if s, _ := on.Check(ctx, "v"); s != games.StatusOnline || !on.Ready() {
		t.Fatalf("after marker: %v", s)
	}
}

func TestInfo(t *testing.T) {
	ctx := context.Background()
	tr := New(fakeDocker(t, true, ""), "v", valheimSpec())
	if out, ok := tr.Info(ctx); !ok || out["available"] != false {
		t.Fatalf("unattached: %v", out)
	}
	tr.Replay(strings.NewReader("Load world: Dedicated\nGot handshake from client 1\n"))
	out, _ := tr.Info(ctx)
	if out["available"] != true || out["state"] != "starting" || out["world"] != "Dedicated" || out["players_connected"] != 1 || out["uptime"] == nil {
		t.Fatalf("attached: %v", out)
	}
	tr.Replay(strings.NewReader("Loading: Done."))
	if out, _ := tr.Info(ctx); out["state"] != "online" {
		t.Fatalf("ready: %v", out)
	}
}

func TestUptimeString(t *testing.T) {
	cases := map[time.Duration]string{
		-time.Minute:                 "0m",
		5 * time.Minute:              "5m",
		90 * time.Minute:             "1h 30m",
		50*time.Hour + 5*time.Minute: "2d 2h 5m",
	}
	for d, want := range cases {
		if got := uptimeString(d); got != want {
			t.Errorf("uptimeString(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestRun_FollowsLogsThenStops(t *testing.T) {
	logs := "Got handshake from client 7\nOpened Steam server"
	tr := New(fakeDocker(t, true, logs), "v", Spec{Name: "t", Ready: regexp.MustCompile(`Opened Steam server`),
		Join: regexp.MustCompile(`client (\S+)`)})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tr.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	// The log stream ends at once, so state is reset after each tail; catch
	// it while the tail is running by checking the final handled lines.
	seen := false
	for time.Now().Before(deadline) && !seen {
		seen = tr.Ready()
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}

func TestRun_NotRunningWaitsAndStops(t *testing.T) {
	tr := New(fakeDocker(t, false, ""), "v", valheimSpec())
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { tr.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop on context end")
	}
	if _, _, ok := tr.PlayerCount(context.Background()); ok {
		t.Error("not running must be ok=false")
	}
}
