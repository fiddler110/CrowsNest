// Package dockerctl talks to Docker through the Engine HTTP API (see http.go, create.go and exec.go): reads, create,
// start, stop, exec. There is no docker CLI or compose in the image. The one process it still starts is nvidia-smi,
// for host GPU stats.
//
// Unix-only (relies on process groups for reliable timeout cancellation),
// which matches the project's Linux-only runtime (Alpine container image,
// docker.sock group access).
package dockerctl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultShortTimeout = 10 * time.Second
	// defaultStopTimeout must exceed every game's stop_grace_period (docker
	// stop returns once the container has exited, which can take the full
	// grace period while the game saves) — Valheim's is 2m.
	defaultStopTimeout  = 5 * time.Minute
	defaultStartTimeout = time.Minute
	defaultGPUTimeout   = 5 * time.Second

	// waitDelay bounds how long Wait may take to return after a timeout
	// cancels a command, in case killing the process group doesn't close
	// every inherited pipe descriptor promptly.
	waitDelay = 5 * time.Second
)

// newCmd builds a command whose entire process group (not just the direct
// child) is killed when ctx is done. exec.CommandContext's default
// cancellation only signals the direct child, which can leave a hung Wait()
// if that child has already forked a grandchild holding the stdout/stderr
// pipes open (e.g. a shell wrapper execing a long-running subprocess).
func newCmd(ctx context.Context, bin string, args ...string) *exec.Cmd {
	// #nosec G204 -- bin is the docker/nvidia-smi binary (operator-set, never request input); args are built
	// here from registry config (container/compose names), passed as an argv list with no shell involved.
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = waitDelay
	return cmd
}

// Target identifies the container to start.
type Target struct {
	ContainerName string
}

// Stats is a snapshot of `docker stats` for one container.
type Stats struct {
	CPUPercent string
	MemUsed    string
	MemTotal   string
	MemPercent string
	// MemUsedBytes is MemUsed unrounded; zero from the CLI fallback.
	MemUsedBytes uint64
}

// GPUStats is a host-level (not per-container) GPU utilization/memory
// snapshot from nvidia-smi.
type GPUStats struct {
	UtilPercent string
	MemUsedMiB  string
	MemTotalMiB string
}

// Client talks to the Docker Engine API. The zero value is ready to use.
type Client struct {
	// Host is where the engine (or the guard in front of it) listens: "unix:///var/run/docker.sock", "tcp://host:2375"
	// or "http://host:2375". Empty means $DOCKER_HOST, then the local socket. TLS and ssh hosts are not supported.
	Host string

	// NvidiaSmiBin overrides the nvidia-smi binary/path used by GPUStats;
	// defaults to "nvidia-smi". Unaffected by Host — GPU stats are read
	// straight from the host's nvidia-smi, not through the Docker API.
	NvidiaSmiBin string

	// Timeout, when non-zero, overrides every operation's default timeout.
	// Intended for tests; production callers should leave it unset.
	Timeout time.Duration

	// HTTP, when non-nil, is the client used for Engine API requests
	// (tests; also lets callers supply their own transport). When nil a
	// client is built from Host: a unix socket dialer or plain HTTP.
	HTTP *http.Client

	mu      sync.Mutex
	httpc   *http.Client
	apiVer  string
	samples map[string]cpuSample

	gpuMu      sync.Mutex
	gpuAt      time.Time // when gpuStats/gpuOK were read
	gpuStats   GPUStats
	gpuOK      bool
	gpuMissing bool // nvidia-smi not installed; retry only after gpuMissingRetry
}

const (
	gpuCacheTTL     = 2 * time.Second
	gpuMissingRetry = 10 * time.Minute
)

func (c *Client) nvidiaSmiBin() string {
	if c.NvidiaSmiBin != "" {
		return c.NvidiaSmiBin
	}
	return "nvidia-smi"
}

// Start starts an existing container (a started one is left running). Containers are created by the dashboard
// (managed games) or by whoever set a hand-configured game up; there is no compose here to create one.
func (c *Client) Start(ctx context.Context, t Target) error {
	ctx, cancel := c.opCtx(ctx, defaultStartTimeout)
	defer cancel()
	resp, err := c.send(ctx, http.MethodPost, "/containers/"+url.PathEscape(t.ContainerName)+"/start", nil, nil)
	if err != nil {
		var ae *apiError
		if asAPI(err, &ae) && ae.Status == http.StatusNotFound {
			return fmt.Errorf("dockerctl: container %q does not exist: create it on the host, or add the game from the dashboard", t.ContainerName)
		}
		return err
	}
	return resp.Body.Close()
}

// Stop stops the named container and waits for it: the engine answers once the container has exited, which can take
// its whole stop grace period while the game saves.
func (c *Client) Stop(ctx context.Context, name string) error {
	ctx, cancel := c.opCtx(ctx, defaultStopTimeout)
	defer cancel()
	resp, err := c.send(ctx, http.MethodPost, "/containers/"+url.PathEscape(name)+"/stop", nil, nil)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// GPUStats returns a host-level GPU utilization/memory snapshot via
// nvidia-smi (only the first GPU is reported, matching the original
// single-GPU assumption). ok is false whenever the reading can't be
// produced — no GPU, nvidia-smi not installed, unparseable output — which
// is the common case on a host with no GPU and is never surfaced as an
// error, matching the original's silent try/except.
func (c *Client) GPUStats(ctx context.Context) (GPUStats, bool) {
	// Host-wide and polled once per game per refresh, so share one reading
	// instead of forking nvidia-smi each time.
	c.gpuMu.Lock()
	defer c.gpuMu.Unlock()
	ttl := gpuCacheTTL
	if c.gpuMissing {
		ttl = gpuMissingRetry
	}
	if !c.gpuAt.IsZero() && time.Since(c.gpuAt) < ttl {
		return c.gpuStats, c.gpuOK
	}
	g, ok, missing := c.readGPU(ctx)
	c.gpuAt, c.gpuStats, c.gpuOK, c.gpuMissing = time.Now(), g, ok, missing
	return g, ok
}

func (c *Client) readGPU(ctx context.Context) (g GPUStats, ok, missing bool) {
	timeout := defaultGPUTimeout
	if c.Timeout > 0 {
		timeout = c.Timeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := newCmd(runCtx, c.nvidiaSmiBin(), "--query-gpu=utilization.gpu,memory.used,memory.total", "--format=csv,noheader,nounits")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return GPUStats{}, false, errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist)
	}

	line, _, _ := strings.Cut(strings.TrimSpace(stdout.String()), "\n")
	parts := strings.Split(line, ",")
	if len(parts) < 3 {
		return GPUStats{}, false, false
	}
	return GPUStats{
		UtilPercent: strings.TrimSpace(parts[0]),
		MemUsedMiB:  strings.TrimSpace(parts[1]),
		MemTotalMiB: strings.TrimSpace(parts[2]),
	}, true, false
}
