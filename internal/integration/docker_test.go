//go:build integration

// Package integration runs the guard and the Docker client against a real Docker daemon, with a tiny public image.
// The unit tests use fakes everywhere else; this is where a change in what Docker really answers shows up.
//
//	go test -tags integration -count=1 ./internal/integration
package integration

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/dockerguard"
)

const (
	image     = "busybox:1.37"
	imageRepo = "docker.io/library/busybox"
)

func socket() string {
	if s := os.Getenv("DOCKER_SOCKET"); s != "" {
		return s
	}
	return "/var/run/docker.sock"
}

func TestStartStopThroughTheGuard(t *testing.T) {
	if _, err := os.Stat(socket()); err != nil {
		t.Skipf("no Docker socket at %s", socket())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	name := "crowsnest-it-" + time.Now().Format("150405")
	g := dockerguard.New(socket(), []*dockerguard.Scope{{
		Name:     name,
		Images:   map[string]bool{imageRepo: true},
		Networks: map[string]bool{"bridge": true},
	}})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { _ = g.ServeContext(gctx, l) }()

	// Pulling needs the daemon directly: the guard only serves what a scope allows, and the image is test setup.
	direct := &dockerctl.Client{Host: "unix://" + socket()}
	if err := direct.Pull(ctx, image); err != nil {
		t.Fatalf("pull %s: %v", image, err)
	}
	via := &dockerctl.Client{Host: "tcp://" + l.Addr().String()}
	t.Cleanup(func() { _ = direct.Remove(context.Background(), name) })

	if err := via.Ping(ctx); err != nil {
		t.Fatalf("ping through the guard: %v", err)
	}
	spec := dockerctl.CreateSpec{Name: name, Image: image, Network: "bridge", Entrypoint: []string{"sleep", "300"}, StopTimeout: 1}
	if err := via.Create(ctx, spec); err != nil {
		t.Fatalf("create through the guard: %v", err)
	}
	if err := via.Start(ctx, dockerctl.Target{ContainerName: name}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if up, err := via.Running(ctx, name); err != nil || !up {
		t.Fatalf("running = %v, %v", up, err)
	}
	if out, err := via.Stats(ctx, name); err != nil || out.MemUsedBytes == 0 {
		t.Errorf("stats = %+v, %v", out, err)
	}
	if err := via.Stop(ctx, name); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if up, _ := via.Running(ctx, name); up {
		t.Error("still running after stop")
	}
	if err := via.Remove(ctx, name); err != nil {
		t.Errorf("remove: %v", err)
	}
}

func TestGuardRefusesWhatTheScopeDoesNotAllow(t *testing.T) {
	if _, err := os.Stat(socket()); err != nil {
		t.Skipf("no Docker socket at %s", socket())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	name := "crowsnest-it-deny-" + time.Now().Format("150405")
	g := dockerguard.New(socket(), []*dockerguard.Scope{{Name: name, Images: map[string]bool{imageRepo: true}, Networks: map[string]bool{"bridge": true}}})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { _ = g.ServeContext(gctx, l) }()
	via := &dockerctl.Client{Host: "tcp://" + l.Addr().String()}
	direct := &dockerctl.Client{Host: "unix://" + socket()}
	t.Cleanup(func() {
		_ = direct.Remove(context.Background(), name)
		_ = direct.Remove(context.Background(), name+"x")
	})

	for what, s := range map[string]dockerctl.CreateSpec{
		"another image":     {Name: name, Image: "alpine:3", Network: "bridge"},
		"a host bind":       {Name: name, Image: image, Network: "bridge", Binds: []string{"/etc:/host"}},
		"another network":   {Name: name, Image: image, Network: "host"},
		"another name":      {Name: name + "x", Image: image, Network: "bridge"},
		"a security option": {Name: name, Image: image, Network: "bridge", SecOpts: []string{"seccomp=unconfined"}},
	} {
		err := via.Create(ctx, s)
		if err == nil {
			t.Errorf("%s: the guard let the create through", what)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), "403") && !strings.Contains(strings.ToLower(err.Error()), "forbidden") && !strings.Contains(strings.ToLower(err.Error()), "not allowed") {
			t.Logf("%s: refused with %v", what, err)
		}
	}
	if ok, _ := direct.Exists(ctx, name); ok {
		t.Error("a refused create left a container behind")
	}
}
