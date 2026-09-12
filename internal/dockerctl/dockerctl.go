// Package dockerctl wraps the docker/docker-compose CLI: every process this
// application spawns to control a game server container goes through here.
// It shells out rather than using the Docker Engine SDK so that compose
// profiles/services (used to keep game servers out of a bare `docker compose
// up`) map directly onto CLI commands, matching the container image's staged
// docker CLI + compose plugin.
//
// Unix-only (relies on process groups for reliable timeout cancellation),
// which matches the project's Linux-only runtime (Alpine container image,
// docker.sock group access).
package dockerctl

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	defaultShortTimeout = 10 * time.Second
	defaultStopTimeout  = 60 * time.Second
	defaultStartTimeout = 120 * time.Second
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
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = waitDelay
	return cmd
}

func (c *Client) newCmd(ctx context.Context, args ...string) *exec.Cmd {
	if c.Host != "" {
		// The docker CLI's -H flag is global: it must precede the
		// subcommand ("docker -H <host> ps ...", "docker -H <host> compose
		// -f ... up -d ..."), which prepending here guarantees regardless
		// of which operation called us.
		args = append([]string{"-H", c.Host}, args...)
	}
	return newCmd(ctx, c.bin(), args...)
}

// Target identifies a container plus, for one that may not exist yet, the
// compose file/profile/service used to create it.
type Target struct {
	ContainerName  string
	ComposeFile    string
	ComposeProfile string
	ComposeService string
}

// Stats is a snapshot of `docker stats` for one container.
type Stats struct {
	CPUPercent string
	MemUsed    string
	MemTotal   string
	MemPercent string
}

// GPUStats is a host-level (not per-container) GPU utilization/memory
// snapshot from nvidia-smi.
type GPUStats struct {
	UtilPercent string
	MemUsedMiB  string
	MemTotalMiB string
}

// Client runs docker CLI commands. The zero value is ready to use.
type Client struct {
	// DockerBin overrides the docker binary/path; defaults to "docker".
	DockerBin string

	// Host, when non-empty, is passed as the docker CLI's global `-H` flag
	// on every invocation (e.g. "tcp://docker-socket-proxy:2375"), so every
	// command — including `docker compose` — is issued against a remote
	// daemon or a docker-socket-proxy instead of the local
	// /var/run/docker.sock. Empty (the default) leaves the docker CLI to
	// its own resolution (DOCKER_HOST env var, then the local socket),
	// which is what a direct socket-mount deployment wants.
	Host string

	// NvidiaSmiBin overrides the nvidia-smi binary/path used by GPUStats;
	// defaults to "nvidia-smi". Unaffected by Host — GPU stats are read
	// straight from the host's nvidia-smi, not through the Docker API.
	NvidiaSmiBin string

	// Timeout, when non-zero, overrides every operation's default timeout.
	// Intended for tests; production callers should leave it unset.
	Timeout time.Duration
}

func (c *Client) bin() string {
	if c.DockerBin != "" {
		return c.DockerBin
	}
	return "docker"
}

func (c *Client) nvidiaSmiBin() string {
	if c.NvidiaSmiBin != "" {
		return c.NvidiaSmiBin
	}
	return "nvidia-smi"
}

// run executes `docker <args...>`, returning trimmed stdout. defaultTimeout
// applies unless c.Timeout overrides it.
func (c *Client) run(ctx context.Context, defaultTimeout time.Duration, args ...string) (string, error) {
	timeout := defaultTimeout
	if c.Timeout > 0 {
		timeout = c.Timeout
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := c.newCmd(runCtx, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("dockerctl: %s %s: timed out after %s", c.bin(), strings.Join(args, " "), timeout)
		}
		return "", fmt.Errorf("dockerctl: %s %s: %w: %s", c.bin(), strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// exists reports whether a container by this name exists (running or not).
func (c *Client) exists(ctx context.Context, name string) (bool, error) {
	out, err := c.run(ctx, defaultShortTimeout, "ps", "-a", "--filter", "name=^"+name+"$", "--format", "{{.Names}}")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) != "", nil
}

// Running reports whether the container is currently running.
func (c *Client) Running(ctx context.Context, name string) (bool, error) {
	out, err := c.run(ctx, defaultShortTimeout, "ps", "--filter", "name=^"+name+"$", "--format", "{{.Names}}")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) != "", nil
}

// Start starts the target's container. If the container already exists
// (from a previous run) it's simply started; otherwise it's created via
// `docker compose up -d` against the target's compose file/profile/service.
func (c *Client) Start(ctx context.Context, t Target) error {
	exists, err := c.exists(ctx, t.ContainerName)
	if err != nil {
		return err
	}
	if exists {
		_, err := c.run(ctx, defaultStartTimeout, "start", t.ContainerName)
		return err
	}

	if t.ComposeFile == "" {
		return fmt.Errorf("dockerctl: container %q does not exist and no compose file is configured", t.ContainerName)
	}
	args := []string{"compose", "-f", t.ComposeFile}
	if t.ComposeProfile != "" {
		args = append(args, "--profile", t.ComposeProfile)
	}
	args = append(args, "up", "-d", t.ComposeService)
	_, err = c.run(ctx, defaultStartTimeout, args...)
	return err
}

// Stop stops the named container.
func (c *Client) Stop(ctx context.Context, name string) error {
	_, err := c.run(ctx, defaultStopTimeout, "stop", name)
	return err
}

// StartedAt returns the container's current-run start time.
func (c *Client) StartedAt(ctx context.Context, name string) (time.Time, error) {
	out, err := c.run(ctx, defaultShortTimeout, "inspect", "--format", "{{.State.StartedAt}}", name)
	if err != nil {
		return time.Time{}, err
	}
	ts := strings.TrimSpace(out)
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, fmt.Errorf("dockerctl: parse StartedAt %q: %w", ts, err)
	}
	return t, nil
}

// Exec runs `docker exec <name> <args...>` and returns its stdout. Used by
// per-game StatusCheckers that need to inspect state inside the container
// (e.g. grep a log file for a readiness marker).
func (c *Client) Exec(ctx context.Context, name string, args ...string) (string, error) {
	full := append([]string{"exec", name}, args...)
	return c.run(ctx, defaultShortTimeout, full...)
}

// Logs streams `docker logs -f` for the named container. since and tail are
// passed through to the docker CLI verbatim when non-empty (since accepts
// docker's RFC3339 or relative syntax, e.g. "1h"). The caller must cancel
// ctx to stop the stream and release the underlying process.
func (c *Client) Logs(ctx context.Context, name, since, tail string) (io.ReadCloser, error) {
	args := []string{"logs", "-f"}
	if since != "" {
		args = append(args, "--since", since)
	}
	if tail != "" {
		args = append(args, "--tail", tail)
	}
	args = append(args, name)

	cmd := c.newCmd(ctx, args...)
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, fmt.Errorf("dockerctl: start %s %s: %w", c.bin(), strings.Join(args, " "), err)
	}

	go func() {
		pw.CloseWithError(cmd.Wait())
	}()

	return pr, nil
}

// Stats returns a `docker stats --no-stream` snapshot for the named
// container.
func (c *Client) Stats(ctx context.Context, name string) (Stats, error) {
	out, err := c.run(ctx, defaultShortTimeout, "stats", "--no-stream", "--format", "{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}", name)
	if err != nil {
		return Stats{}, err
	}

	var s Stats
	parts := strings.Split(strings.TrimSpace(out), "\t")
	if len(parts) >= 1 {
		s.CPUPercent = strings.TrimSuffix(strings.TrimSpace(parts[0]), "%")
	}
	if len(parts) >= 2 {
		if used, total, ok := strings.Cut(parts[1], "/"); ok {
			s.MemUsed = strings.TrimSpace(used)
			s.MemTotal = strings.TrimSpace(total)
		}
	}
	if len(parts) >= 3 {
		s.MemPercent = strings.TrimSuffix(strings.TrimSpace(parts[2]), "%")
	}
	return s, nil
}

// GPUStats returns a host-level GPU utilization/memory snapshot via
// nvidia-smi (only the first GPU is reported, matching the original
// single-GPU assumption). ok is false whenever the reading can't be
// produced — no GPU, nvidia-smi not installed, unparseable output — which
// is the common case on a host with no GPU and is never surfaced as an
// error, matching the original's silent try/except.
func (c *Client) GPUStats(ctx context.Context) (GPUStats, bool) {
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
		return GPUStats{}, false
	}

	line, _, _ := strings.Cut(strings.TrimSpace(stdout.String()), "\n")
	parts := strings.Split(line, ",")
	if len(parts) < 3 {
		return GPUStats{}, false
	}
	return GPUStats{
		UtilPercent: strings.TrimSpace(parts[0]),
		MemUsedMiB:  strings.TrimSpace(parts[1]),
		MemTotalMiB: strings.TrimSpace(parts[2]),
	}, true
}
