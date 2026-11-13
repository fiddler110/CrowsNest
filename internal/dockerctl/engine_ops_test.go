package dockerctl_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/dockerctl/dockertest"
)

func TestStartStop(t *testing.T) {
	f := dockertest.New(t)
	f.Add("pal", false)
	c := f.Client()
	ctx := context.Background()

	if err := c.Start(ctx, dockerctl.Target{ContainerName: "pal"}); err != nil || !f.Running("pal") {
		t.Fatalf("Start = %v, running = %v", err, f.Running("pal"))
	}
	if err := c.Start(ctx, dockerctl.Target{ContainerName: "pal"}); err != nil { // a started one is left alone
		t.Fatalf("Start of a running container = %v", err)
	}
	if err := c.Stop(ctx, "pal"); err != nil || f.Running("pal") {
		t.Fatalf("Stop = %v, running = %v", err, f.Running("pal"))
	}
}

func TestStart_MissingContainerSaysWhatToDo(t *testing.T) {
	c := dockertest.New(t).Client()
	err := c.Start(context.Background(), dockerctl.Target{ContainerName: "ghost"})
	if err == nil || !strings.Contains(err.Error(), "does not exist") || !strings.Contains(err.Error(), "dashboard") {
		t.Fatalf("err = %v", err)
	}
}

func TestStart_GuardDenialIsReported(t *testing.T) {
	f := dockertest.New(t)
	f.Add("pal", false)
	f.FailStart("pal", 403)
	err := f.Client().Start(context.Background(), dockerctl.Target{ContainerName: "pal"})
	if err == nil || !dockerctl.IsDenied(err) {
		t.Fatalf("err = %v, want a denial", err)
	}
}

func TestExec_StdoutAndStderr(t *testing.T) {
	f := dockertest.New(t)
	f.Add("pal", true)
	f.Exec = func(container string, cmd []string, stdin string) (string, string, int) {
		if container != "pal" || strings.Join(cmd, " ") != "ls -l /data" {
			t.Errorf("exec %s %v", container, cmd)
		}
		return "total 0\n", "noise\n", 0
	}
	out, err := f.Client().Exec(context.Background(), "pal", "ls", "-l", "/data")
	if err != nil || out != "total 0\n" {
		t.Fatalf("Exec = %q, %v", out, err)
	}
}

func TestExec_NonZeroExitCarriesStderr(t *testing.T) {
	f := dockertest.New(t)
	f.Add("pal", true)
	f.Exec = func(string, []string, string) (string, string, int) { return "", "disk full\n", 3 }
	_, err := f.Client().Exec(context.Background(), "pal", "backup")
	if err == nil || !strings.Contains(err.Error(), "exit status 3") || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err = %v", err)
	}
}

func TestExecStdin_SendsInputUntilEOF(t *testing.T) {
	f := dockertest.New(t)
	f.Add("pal", true)
	var got string
	f.Exec = func(_ string, _ []string, stdin string) (string, string, int) { got = stdin; return "ok", "", 0 }
	big := strings.Repeat("0123456789", 20000) // well past one read
	out, err := f.Client().ExecStdin(context.Background(), "pal", strings.NewReader(big), time.Minute, "sh", "-c", "cat > /x")
	if err != nil || out != "ok" {
		t.Fatalf("ExecStdin = %q, %v", out, err)
	}
	if got != big {
		t.Fatalf("the command read %d bytes, want %d", len(got), len(big))
	}
}

func TestExec_MissingContainer(t *testing.T) {
	_, err := dockertest.New(t).Client().Exec(context.Background(), "ghost", "true")
	if err == nil {
		t.Fatal("exec in a missing container should fail")
	}
}

func TestExec_TimeoutEndsABlockedCommand(t *testing.T) {
	f := dockertest.New(t)
	f.Add("pal", true)
	f.Exec = func(string, []string, string) (string, string, int) { time.Sleep(2 * time.Second); return "", "", 0 }
	c := f.Client()
	start := time.Now()
	_, err := c.ExecTimeout(context.Background(), "pal", 200*time.Millisecond, "sleep")
	if err == nil || !strings.Contains(err.Error(), "timed out") || time.Since(start) > time.Second {
		t.Fatalf("err = %v after %s", err, time.Since(start))
	}
}
