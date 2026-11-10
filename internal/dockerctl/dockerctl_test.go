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

func TestCLI_Running_True(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
if [ "$1" = "ps" ]; then
  echo "windrose"
fi
`)
	running, err := c.cliRunning(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Running() error = %v", err)
	}
	if !running {
		t.Error("Running() = false, want true")
	}
}

func TestCLI_Running_False(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
if [ "$1" = "ps" ]; then
  :
fi
`)
	running, err := c.cliRunning(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Running() error = %v", err)
	}
	if running {
		t.Error("Running() = true, want false")
	}
}

// TestStart_ExistingContainerStillUsesCompose: with a compose file
// configured, Start always goes through `compose up -d` (which starts an
// existing container as-is, or recreates it if its config changed) rather
// than a bare `docker start` that would silently keep a stale config.
func TestStart_ExistingContainerStillUsesCompose(t *testing.T) {
	c, logPath := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
case "$1" in
  ps) echo "windrose" ;;
  start) exit 0 ;;
  compose) exit 0 ;;
esac
`)
	tgt := Target{ContainerName: "windrose", ComposeFile: "/windrose/compose.yaml", ComposeProfile: "windrose", ComposeService: "windrose"}
	if err := c.Start(context.Background(), tgt); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	invocations := readInvocations(t, logPath)
	want := "compose -f /windrose/compose.yaml --profile windrose up -d windrose"
	var sawCompose bool
	for _, line := range invocations {
		if line == "start windrose" {
			t.Fatalf("unexpected bare docker start with a compose file configured: %v", invocations)
		}
		if line == want {
			sawCompose = true
		}
	}
	if !sawCompose {
		t.Fatalf("invocations = %v, want %q", invocations, want)
	}
}

func TestStart_NoComposeFileExistingContainer(t *testing.T) {
	c, logPath := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
case "$1" in
  ps) echo "windrose" ;;
  start) exit 0 ;;
esac
`)
	if err := c.Start(context.Background(), Target{ContainerName: "windrose"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	invocations := readInvocations(t, logPath)
	if invocations[len(invocations)-1] != "start windrose" {
		t.Fatalf("invocations = %v, want a final %q", invocations, "start windrose")
	}
}

func TestCLI_FinishedAt(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
case "$4" in
  palworld) echo "2026-11-06T22:00:00.5Z" ;;
  fresh) echo "0001-01-01T00:00:00Z" ;;
esac
`)
	got, err := c.cliFinishedAt(context.Background(), "palworld")
	if err != nil || got.UTC().Format(time.RFC3339) != "2026-11-06T22:00:00Z" {
		t.Fatalf("FinishedAt(palworld) = %v, %v", got, err)
	}
	got, err = c.cliFinishedAt(context.Background(), "fresh")
	if err != nil || !got.IsZero() {
		t.Fatalf("FinishedAt(never stopped) = %v, %v, want zero time", got, err)
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

func TestCLI_StartedAt(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
[ "$1" = "inspect" ] && echo "2026-01-02T03:04:05.123456789Z"
`)
	got, err := c.cliStartedAt(context.Background(), "windrose")
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

func TestCLI_Stats(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
[ "$1" = "stats" ] && printf '12.34%%\t100MiB / 512MiB\t19.53%%\n'
`)
	s, err := c.cliStats(context.Background(), "windrose")
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	want := Stats{CPUPercent: "12.34", MemUsed: "100MiB", MemTotal: "512MiB", MemPercent: "19.53"}
	if s != want {
		t.Fatalf("Stats() = %+v, want %+v", s, want)
	}
}

// newFakeBin writes script as an executable file and returns its path.
func newFakeBin(t *testing.T, name, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	return path
}

func TestGPUStats_CachesReading(t *testing.T) {
	count := filepath.Join(t.TempDir(), "count")
	bin := newFakeBin(t, "nvidia-smi", "#!/bin/sh\necho x >> "+count+"\necho '45, 2048, 8192'\n")
	c := &Client{NvidiaSmiBin: bin}
	for i := 0; i < 3; i++ {
		if _, ok := c.GPUStats(context.Background()); !ok {
			t.Fatal("GPUStats() ok = false, want true")
		}
	}
	b, _ := os.ReadFile(count)
	if n := strings.Count(string(b), "x"); n != 1 {
		t.Fatalf("nvidia-smi ran %d times, want 1 (cached)", n)
	}
}

func TestGPUStats_MissingBinaryStopsTrying(t *testing.T) {
	c := &Client{NvidiaSmiBin: filepath.Join(t.TempDir(), "nope")}
	if _, ok := c.GPUStats(context.Background()); ok {
		t.Fatal("ok = true, want false")
	}
	if !c.gpuMissing {
		t.Fatal("gpuMissing = false, want true after a missing binary")
	}
}

func TestGPUStats_Success(t *testing.T) {
	c := &Client{NvidiaSmiBin: newFakeBin(t, "nvidia-smi", "#!/bin/sh\nprintf '45, 2048, 8192\\n'\n")}
	g, ok := c.GPUStats(context.Background())
	if !ok {
		t.Fatal("GPUStats() ok = false, want true")
	}
	want := GPUStats{UtilPercent: "45", MemUsedMiB: "2048", MemTotalMiB: "8192"}
	if g != want {
		t.Fatalf("GPUStats() = %+v, want %+v", g, want)
	}
}

func TestGPUStats_Unavailable(t *testing.T) {
	c := &Client{NvidiaSmiBin: filepath.Join(t.TempDir(), "does-not-exist")}
	g, ok := c.GPUStats(context.Background())
	if ok {
		t.Fatalf("GPUStats() ok = true, want false when nvidia-smi is unavailable; got %+v", g)
	}
}

func TestGPUStats_MalformedOutput(t *testing.T) {
	c := &Client{NvidiaSmiBin: newFakeBin(t, "nvidia-smi", "#!/bin/sh\nprintf 'not what we expected\\n'\n")}
	g, ok := c.GPUStats(context.Background())
	if ok {
		t.Fatalf("GPUStats() ok = true, want false for malformed output; got %+v", g)
	}
}

func TestCLI_Logs(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\necho line1\necho line2\n")
	rc, err := c.cliLogs(context.Background(), "windrose", "", "")
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
	_, err := c.cliRunning(context.Background(), "windrose")
	if err == nil {
		t.Fatal("Running() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error = %q, want it to include the process's stderr", err.Error())
	}
}

func TestHost_PrependsGlobalFlag(t *testing.T) {
	c, logPath := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+`
[ "$3" = "stop" ] && exit 0
`)
	c.Host = "tcp://docker-socket-proxy:2375"
	if err := c.Stop(context.Background(), "windrose"); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	invocations := readInvocations(t, logPath)
	want := "-H tcp://docker-socket-proxy:2375 stop windrose"
	if len(invocations) != 1 || invocations[0] != want {
		t.Fatalf("invocations = %v, want [%q]", invocations, want)
	}
}

func TestRun_Timeout(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\nsleep 5\n")
	c.Timeout = 50 * time.Millisecond
	_, err := c.cliRunning(context.Background(), "windrose")
	if err == nil {
		t.Fatal("Running() error = nil, want timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %q, want a timeout error", err.Error())
	}
}

func TestStart_PullRunsBeforeUp(t *testing.T) {
	c, logPath := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+"exit 0\n")
	tgt := Target{ContainerName: "w", ComposeFile: "/c.yaml", ComposeService: "w", Pull: true}
	if err := c.Start(context.Background(), tgt); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	got := readInvocations(t, logPath)
	want := []string{"compose -f /c.yaml pull w", "compose -f /c.yaml up -d w"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("invocations = %v, want %v", got, want)
	}
}

func TestStart_FailedPullStillStarts(t *testing.T) {
	c, logPath := newFakeDocker(t, "#!/bin/sh\n"+logInvocation+"[ \"$4\" = pull ] && exit 1\nexit 0\n")
	tgt := Target{ContainerName: "w", ComposeFile: "/c.yaml", ComposeService: "w", Pull: true}
	if err := c.Start(context.Background(), tgt); err != nil {
		t.Fatalf("Start() error = %v, want a failed pull to be tolerated", err)
	}
	got := readInvocations(t, logPath)
	if len(got) != 2 || got[1] != "compose -f /c.yaml up -d w" {
		t.Fatalf("invocations = %v, want up after the failed pull", got)
	}
}

func TestCLI_Ping(t *testing.T) {
	c, _ := newFakeDocker(t, "#!/bin/sh\necho 29.0.0\n")
	if err := c.cliPing(context.Background()); err != nil {
		t.Fatalf("Ping() = %v, want nil", err)
	}
	down, _ := newFakeDocker(t, "#!/bin/sh\necho 'Cannot connect to the Docker daemon' >&2\nexit 1\n")
	if err := down.cliPing(context.Background()); err == nil {
		t.Fatal("Ping() = nil against a failing daemon, want an error")
	}
}
