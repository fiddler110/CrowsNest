package dockerctl

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultDockerHost = "unix:///var/run/docker.sock"
	// fallbackAPIVersion is used when /_ping carries no API-Version header.
	fallbackAPIVersion = "1.44"
	// sampleMaxAge is how old a cached stats sample may be before it is
	// discarded in favour of the slow (engine-computed precpu) path.
	sampleMaxAge = 60 * time.Second
)

// apiError is a non-2xx Engine API response.
type apiError struct {
	Status  int
	Message string
	What    string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("dockerctl: %s: HTTP %d: %s", e.What, e.Status, e.Message)
}

func isNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// resolvedHost returns the effective daemon address.
func (c *Client) resolvedHost() string {
	h := strings.TrimSpace(c.Host)
	if h == "" {
		h = strings.TrimSpace(os.Getenv("DOCKER_HOST"))
	}
	if h == "" {
		h = defaultDockerHost
	}
	return h
}

// target splits the host into the base URL requests are built from and, for
// a unix socket, the socket path. ok is false for schemes the HTTP path does
// not handle (https, ssh, npipe).
func (c *Client) target() (base, socket string, ok bool) {
	h := c.resolvedHost()
	switch {
	case strings.HasPrefix(h, "unix://"):
		return "http://docker", strings.TrimPrefix(h, "unix://"), true
	case strings.HasPrefix(h, "tcp://"):
		return "http://" + strings.TrimSuffix(strings.TrimPrefix(h, "tcp://"), "/"), "", true
	case strings.HasPrefix(h, "http://"):
		return strings.TrimSuffix(h, "/"), "", true
	}
	return "", "", false
}

// useCLI reports whether the read operations must use the docker CLI
// instead of the HTTP API: TLS (DOCKER_TLS_VERIFY / DOCKER_CERT_PATH with a
// TCP host, or an https/ssh/npipe host) is not implemented here, so those
// configurations keep working through the CLI rather than breaking.
func (c *Client) useCLI() bool {
	if c.HTTP != nil {
		return false
	}
	// An explicit DockerBin means the caller wants that binary used (the
	// production wiring never sets it; tests use it to fake docker).
	if c.DockerBin != "" {
		return true
	}
	_, socket, ok := c.target()
	if !ok {
		return true
	}
	return socket == "" && (os.Getenv("DOCKER_TLS_VERIFY") != "" || os.Getenv("DOCKER_CERT_PATH") != "")
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.httpc == nil {
		_, socket, _ := c.target()
		tr := &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 4, IdleConnTimeout: 90 * time.Second}
		if socket != "" {
			tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			}
		}
		c.httpc = &http.Client{Transport: tr}
	}
	return c.httpc
}

func (c *Client) opCtx(ctx context.Context, def time.Duration) (context.Context, context.CancelFunc) {
	if c.Timeout > 0 {
		def = c.Timeout
	}
	return context.WithTimeout(ctx, def)
}

// do issues a GET and returns the response for 2xx; otherwise it drains the
// body into an *apiError carrying the engine's message.
func (c *Client) do(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	base, _, _ := c.target()
	u := base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("dockerctl: GET %s: %w", path, err)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("dockerctl: GET %s: %w", path, err)
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		msg := strings.TrimSpace(string(data))
		var m struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &m) == nil && m.Message != "" {
			msg = m.Message
		}
		return nil, &apiError{Status: resp.StatusCode, Message: msg, What: "GET " + path}
	}
	return resp, nil
}

// ping hits /_ping and caches the negotiated API version.
func (c *Client) ping(ctx context.Context) (string, error) {
	resp, err := c.do(ctx, "/_ping", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	v := resp.Header.Get("API-Version")
	if v == "" {
		v = fallbackAPIVersion
	}
	c.mu.Lock()
	c.apiVer = v
	c.mu.Unlock()
	return v, nil
}

// versioned returns "/v<version>" + path, negotiating the version once.
func (c *Client) versioned(ctx context.Context, path string) (string, error) {
	c.mu.Lock()
	v := c.apiVer
	c.mu.Unlock()
	if v == "" {
		var err error
		if v, err = c.ping(ctx); err != nil {
			return "", err
		}
	}
	return "/v" + v + path, nil
}

func (c *Client) get(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	p, err := c.versioned(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, p, q)
}

type inspectResp struct {
	ID    string `json:"Id"`
	State struct {
		Running    bool
		StartedAt  string
		FinishedAt string
	}
	Config struct {
		Tty bool
	}
}

func (c *Client) inspect(ctx context.Context, name string) (*inspectResp, error) {
	resp, err := c.get(ctx, "/containers/"+url.PathEscape(name)+"/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var ir inspectResp
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		return nil, fmt.Errorf("dockerctl: decode inspect %s: %w", name, err)
	}
	return &ir, nil
}

// Ping reports whether the Docker daemon (or the socket proxy in front of it)
// answers. Unlike the status checks it says nothing about any one container;
// it is how the dashboard tells "docker is down" from "every game is offline".
func (c *Client) Ping(ctx context.Context) error {
	if c.useCLI() {
		return c.cliPing(ctx)
	}
	ctx, cancel := c.opCtx(ctx, defaultShortTimeout)
	defer cancel()
	_, err := c.ping(ctx)
	return err
}

// Exists reports whether a container by this name exists, running or not.
func (c *Client) Exists(ctx context.Context, name string) (bool, error) {
	if c.useCLI() {
		return c.cliExists(ctx, name)
	}
	ctx, cancel := c.opCtx(ctx, defaultShortTimeout)
	defer cancel()
	if _, err := c.inspect(ctx, name); err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Running reports whether the container is currently running. A container
// that does not exist is not running (false, nil).
func (c *Client) Running(ctx context.Context, name string) (bool, error) {
	if c.useCLI() {
		return c.cliRunning(ctx, name)
	}
	ctx, cancel := c.opCtx(ctx, defaultShortTimeout)
	defer cancel()
	ir, err := c.inspect(ctx, name)
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return ir.State.Running, nil
}

// StartedAt returns the container's current-run start time.
func (c *Client) StartedAt(ctx context.Context, name string) (time.Time, error) {
	if c.useCLI() {
		return c.cliStartedAt(ctx, name)
	}
	ctx, cancel := c.opCtx(ctx, defaultShortTimeout)
	defer cancel()
	ir, err := c.inspect(ctx, name)
	if err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, ir.State.StartedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("dockerctl: parse StartedAt %q: %w", ir.State.StartedAt, err)
	}
	return t, nil
}

// FinishedAt returns when the container's most recent run ended. It's the
// zero time for a container that has never stopped.
func (c *Client) FinishedAt(ctx context.Context, name string) (time.Time, error) {
	if c.useCLI() {
		return c.cliFinishedAt(ctx, name)
	}
	ctx, cancel := c.opCtx(ctx, defaultShortTimeout)
	defer cancel()
	ir, err := c.inspect(ctx, name)
	if err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, ir.State.FinishedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("dockerctl: parse FinishedAt %q: %w", ir.State.FinishedAt, err)
	}
	if t.Year() <= 1 {
		return time.Time{}, nil // docker reports 0001-01-01 for "never"
	}
	return t, nil
}

// ---- logs ----

// sinceParam converts a docker-CLI style --since value (RFC3339/RFC3339Nano,
// a Go duration such as "1h", or an already-numeric timestamp) into the API's
// "seconds.nanoseconds".
func sinceParam(since string, now time.Time) (string, error) {
	since = strings.TrimSpace(since)
	var t time.Time
	if ts, err := time.Parse(time.RFC3339Nano, since); err == nil {
		t = ts
	} else if d, err := time.ParseDuration(since); err == nil {
		t = now.Add(-d)
	} else if _, err := strconv.ParseFloat(since, 64); err == nil {
		return since, nil
	} else {
		return "", fmt.Errorf("dockerctl: invalid since %q (want RFC3339 or a duration like 1h)", since)
	}
	return fmt.Sprintf("%d.%09d", t.Unix(), t.Nanosecond()), nil
}

type readCloser struct {
	io.Reader
	closers []io.Closer
}

func (r *readCloser) Close() error {
	var first error
	for _, c := range r.closers {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Logs streams the named container's logs with follow. since and tail are
// optional; since accepts RFC3339 or a relative duration such as "1h". The
// caller must cancel ctx or Close the reader to stop the stream.
func (c *Client) Logs(ctx context.Context, name, since, tail string) (io.ReadCloser, error) {
	if c.useCLI() {
		return c.cliLogs(ctx, name, since, tail)
	}
	q := url.Values{"follow": {"1"}, "stdout": {"1"}, "stderr": {"1"}}
	if since != "" {
		s, err := sinceParam(since, time.Now())
		if err != nil {
			return nil, err
		}
		q.Set("since", s)
	}
	if tail != "" {
		q.Set("tail", tail)
	}

	ictx, icancel := c.opCtx(ctx, defaultShortTimeout)
	ir, err := c.inspect(ictx, name)
	icancel()
	if err != nil {
		return nil, err
	}

	resp, err := c.get(ctx, "/containers/"+url.PathEscape(name)+"/logs", q)
	if err != nil {
		return nil, err
	}
	if ir.Config.Tty {
		return resp.Body, nil
	}

	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(demux(pw, resp.Body))
	}()
	return &readCloser{Reader: pr, closers: []io.Closer{pr, resp.Body}}, nil
}

// demux copies the payloads of a multiplexed stream (8-byte header: stream
// type, 3 zero bytes, big-endian uint32 length) to w. Returns nil at a clean
// end of stream.
func demux(w io.Writer, r io.Reader) error {
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		n := int64(binary.BigEndian.Uint32(hdr[4:]))
		if _, err := io.CopyN(w, r, n); err != nil {
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
}

// ---- stats ----

type cpuSample struct {
	id     string
	total  uint64
	system uint64
	at     time.Time
}

type cpuStats struct {
	CPUUsage struct {
		TotalUsage  uint64   `json:"total_usage"`
		PercpuUsage []uint64 `json:"percpu_usage"`
	} `json:"cpu_usage"`
	SystemCPUUsage uint64 `json:"system_cpu_usage"`
	OnlineCPUs     uint32 `json:"online_cpus"`
}

type statsResp struct {
	ID          string   `json:"id"`
	CPUStats    cpuStats `json:"cpu_stats"`
	PreCPUStats cpuStats `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
}

func (c *Client) fetchStats(ctx context.Context, name string, oneShot bool) (*statsResp, error) {
	q := url.Values{"stream": {"false"}}
	if oneShot {
		q.Set("one-shot", "true")
	}
	resp, err := c.get(ctx, "/containers/"+url.PathEscape(name)+"/stats", q)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var sr statsResp
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("dockerctl: decode stats %s: %w", name, err)
	}
	return &sr, nil
}

func onlineCPUs(s cpuStats) float64 {
	if s.OnlineCPUs > 0 {
		return float64(s.OnlineCPUs)
	}
	return float64(len(s.CPUUsage.PercpuUsage))
}

// cpuPercent mirrors the docker CLI's calculation.
func cpuPercent(prevTotal, prevSystem uint64, cur cpuStats) float64 {
	if cur.CPUUsage.TotalUsage < prevTotal || cur.SystemCPUUsage < prevSystem {
		return 0
	}
	cpuDelta := float64(cur.CPUUsage.TotalUsage - prevTotal)
	sysDelta := float64(cur.SystemCPUUsage - prevSystem)
	if cpuDelta > 0 && sysDelta > 0 {
		return cpuDelta / sysDelta * onlineCPUs(cur) * 100
	}
	return 0
}

// memUsed is usage minus the inactive file cache, as `docker stats` shows.
func memUsed(usage uint64, st map[string]uint64) uint64 {
	if v, ok := st["total_inactive_file"]; ok && v < usage { // cgroup v1
		return usage - v
	}
	if v, ok := st["inactive_file"]; ok && v < usage { // cgroup v2
		return usage - v
	}
	return usage
}

var byteUnits = []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"}

// bytesSize mirrors go-units BytesSize (binary units, 4 significant digits).
func bytesSize(size float64) string {
	i := 0
	for size >= 1024 && i < len(byteUnits)-1 {
		size /= 1024
		i++
	}
	return fmt.Sprintf("%.4g%s", size, byteUnits[i])
}

func (c *Client) takeSample(name string) (cpuSample, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.samples[name]
	if !ok || time.Since(s.at) > sampleMaxAge {
		delete(c.samples, name)
		return cpuSample{}, false
	}
	return s, true
}

func (c *Client) putSample(name string, sr *statsResp) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.samples == nil {
		c.samples = map[string]cpuSample{}
	}
	c.samples[name] = cpuSample{id: sr.ID, total: sr.CPUStats.CPUUsage.TotalUsage, system: sr.CPUStats.SystemCPUUsage, at: time.Now()}
}

// Stats returns a `docker stats --no-stream`-style snapshot for the named
// container. The first reading per container is slow (~1s, the engine takes
// two samples); later ones use one-shot and diff against the cached previous
// sample.
func (c *Client) Stats(ctx context.Context, name string) (Stats, error) {
	if c.useCLI() {
		return c.cliStats(ctx, name)
	}
	ctx, cancel := c.opCtx(ctx, defaultShortTimeout)
	defer cancel()

	var (
		sr  *statsResp
		cpu float64
	)
	if prev, ok := c.takeSample(name); ok {
		cur, err := c.fetchStats(ctx, name, true)
		if err != nil {
			return Stats{}, err
		}
		if cur.ID == prev.id &&
			cur.CPUStats.CPUUsage.TotalUsage >= prev.total &&
			cur.CPUStats.SystemCPUUsage > prev.system {
			sr, cpu = cur, cpuPercent(prev.total, prev.system, cur.CPUStats)
		}
		// otherwise: different run, counters went backwards or no time
		// elapsed — fall through to the slow path.
	}
	if sr == nil {
		cur, err := c.fetchStats(ctx, name, false)
		if err != nil {
			return Stats{}, err
		}
		sr, cpu = cur, cpuPercent(cur.PreCPUStats.CPUUsage.TotalUsage, cur.PreCPUStats.SystemCPUUsage, cur.CPUStats)
	}
	c.putSample(name, sr)

	used := memUsed(sr.MemoryStats.Usage, sr.MemoryStats.Stats)
	var memPct float64
	if sr.MemoryStats.Limit > 0 {
		memPct = float64(used) / float64(sr.MemoryStats.Limit) * 100
	}
	return Stats{
		CPUPercent: fmt.Sprintf("%.2f", cpu),
		MemUsed:    bytesSize(float64(used)),
		MemTotal:   bytesSize(float64(sr.MemoryStats.Limit)),
		MemPercent: fmt.Sprintf("%.2f", memPct),
	}, nil
}
