package dockerctl

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newFakeDocker writes script as an executable "docker" replacement and
// returns a Client pointed at it, plus the path to a log file the script is
// expected to append its invocation args to (one line per call) via the
// FAKE_DOCKER_LOG env var.
func newFakeDocker(t *testing.T, script string) (*Client, string) {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "docker")
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	logPath := filepath.Join(dir, "invocations.log")
	t.Setenv("FAKE_DOCKER_LOG", logPath)
	return &Client{DockerBin: binPath}, logPath
}

func readInvocations(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read invocations log: %v", err)
	}
	text := strings.TrimRight(string(data), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

const logInvocation = `echo "$@" >> "$FAKE_DOCKER_LOG"` + "\n"

func TestRunning_True(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
if [ "$1" = "ps" ]; then
  echo "windrose"
fi
`)
	running, err := c.Running(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Running() error = %v", err)
	}
	if !running {
		t.Error("Running() = false, want true")
	}
}

func TestRunning_False(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
if [ "$1" = "ps" ]; then
  :
fi
`)
	running, err := c.Running(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Running() error = %v", err)
	}
	if running {
		t.Error("Running() = true, want false")
	}
}

func TestStart_ExistingContainer(t *testing.T) {
	c, logPath := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
case "$1" in
  ps) echo "windrose" ;;
  start) exit 0 ;;
esac
`)
	tgt := Target{ContainerName: "windrose", ComposeFile: "/windrose/compose.yaml", ComposeProfile: "windrose", ComposeService: "windrose"}
	if err := c.Start(context.Background(), tgt); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	invocations := readInvocations(t, logPath)
	var sawStart bool
	for _, line := range invocations {
		if strings.HasPrefix(line, "compose ") {
			t.Fatalf("unexpected compose invocation for an existing container: %q", line)
		}
		if line == "start windrose" {
			sawStart = true
		}
	}
	if !sawStart {
		t.Fatalf("invocations = %v, want a %q call", invocations, "start windrose")
	}
}

func TestStart_ComposeUpWhenContainerMissing(t *testing.T) {
	c, logPath := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
case "$1" in
  ps) : ;;
  compose) exit 0 ;;
esac
`)
	tgt := Target{ContainerName: "valheim", ComposeFile: "/valheim/compose.yaml", ComposeProfile: "valheim", ComposeService: "valheim"}
	if err := c.Start(context.Background(), tgt); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	invocations := readInvocations(t, logPath)
	want := "compose -f /valheim/compose.yaml --profile valheim up -d valheim"
	var found bool
	for _, line := range invocations {
		if line == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("invocations = %v, want a call %q", invocations, want)
	}
}

func TestStart_NoComposeFileAndContainerMissing(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
case "$1" in
  ps) : ;;
esac
`)
	err := c.Start(context.Background(), Target{ContainerName: "ghost"})
	if err == nil {
		t.Fatal("Start() error = nil, want an error when the container is missing and no compose file is set")
	}
}

func TestStop(t *testing.T) {
	c, logPath := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
[ "$1" = "stop" ] && exit 0
exit 1
`)
	if err := c.Stop(context.Background(), "windrose"); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	invocations := readInvocations(t, logPath)
	if len(invocations) != 1 || invocations[0] != "stop windrose" {
		t.Fatalf("invocations = %v, want [\"stop windrose\"]", invocations)
	}
}

func TestStartedAt(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
[ "$1" = "inspect" ] && echo "2026-01-02T03:04:05.123456789Z"
`)
	got, err := c.StartedAt(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("StartedAt() error = %v", err)
	}
	want := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("StartedAt() = %v, want %v", got, want)
	}
}

func TestExec(t *testing.T) {
	c, logPath := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
[ "$1" = "exec" ] && echo "hello"
`)
	out, err := c.Exec(context.Background(), "windrose", "grep", "-q", "ready", "/log")
	if err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if strings.TrimSpace(out) != "hello" {
		t.Fatalf("Exec() output = %q, want %q", out, "hello")
	}
	invocations := readInvocations(t, logPath)
	want := "exec windrose grep -q ready /log"
	if len(invocations) != 1 || invocations[0] != want {
		t.Fatalf("invocations = %v, want [%q]", invocations, want)
	}
}

func TestStats(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
[ "$1" = "stats" ] && printf '12.34%%\t100MiB / 512MiB\t19.53%%\n'
`)
	s, err := c.Stats(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	want := Stats{CPUPercent: "12.34", MemUsed: "100MiB", MemTotal: "512MiB", MemPercent: "19.53"}
	if s != want {
		t.Fatalf("Stats() = %+v, want %+v", s, want)
	}
}

func TestLogs(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\necho line1\necho line2\n")
	rc, err := c.Logs(context.Background(), "windrose", "", "")
	if err != nil {
		t.Fatalf("Logs() error = %v", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read logs: %v", err)
	}
	if string(data) != "line1\nline2\n" {
		t.Fatalf("Logs() output = %q, want %q", data, "line1\nline2\n")
	}
}

func TestRun_ErrorIncludesStderr(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\necho boom >&2\nexit 1\n")
	_, err := c.Running(context.Background(), "windrose")
	if err == nil {
		t.Fatal("Running() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error = %q, want it to include the process's stderr", err.Error())
	}
}

func TestRun_Timeout(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\nsleep 5\n")
	c.Timeout = 50 * time.Millisecond
	_, err := c.Running(context.Background(), "windrose")
	if err == nil {
		t.Fatal("Running() error = nil, want timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %q, want a timeout error", err.Error())
	}
}
