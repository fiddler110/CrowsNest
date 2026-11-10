package dockerctl

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeEngine is an httptest handler that records request URIs and serves a
// tiny subset of the Engine API under /v1.45.
type fakeEngine struct {
	mu      sync.Mutex
	uris    []string
	tty     bool
	running bool
	stats   []string // successive stats bodies (last repeats)
	logBody []byte
	noVer   bool
}

func (f *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.uris = append(f.uris, r.URL.RequestURI())
	f.mu.Unlock()
	if r.URL.Path == "/_ping" {
		if !f.noVer {
			w.Header().Set("API-Version", "1.45")
		}
		fmt.Fprint(w, "OK")
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/v1.45")
	if p == r.URL.Path && f.noVer {
		p = strings.TrimPrefix(r.URL.Path, "/v1.44")
	}
	if p == r.URL.Path {
		http.Error(w, `{"message":"unversioned"}`, 400)
		return
	}
	switch {
	case strings.HasPrefix(p, "/containers/ghost/"):
		w.WriteHeader(404)
		fmt.Fprint(w, `{"message":"No such container: ghost"}`)
	case strings.HasSuffix(p, "/json"):
		fmt.Fprintf(w, `{"Id":"abc","State":{"Running":%v,"StartedAt":"2026-01-02T03:04:05.123456789Z","FinishedAt":"0001-01-01T00:00:00Z"},"Config":{"Tty":%v}}`, f.running, f.tty)
	case strings.HasSuffix(p, "/logs"):
		w.WriteHeader(200)
		w.Write(f.logBody)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		<-r.Context().Done() // follow: stay open
	case strings.HasSuffix(p, "/stats"):
		f.mu.Lock()
		body := f.stats[0]
		if len(f.stats) > 1 {
			f.stats = f.stats[1:]
		}
		f.mu.Unlock()
		fmt.Fprint(w, body)
	default:
		w.WriteHeader(404)
	}
}

func (f *fakeEngine) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.uris...)
}

func newEngine(t *testing.T, f *fakeEngine) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &Client{Host: "tcp://" + strings.TrimPrefix(srv.URL, "http://")}
}

func frame(stream byte, s string) []byte {
	b := make([]byte, 8, 8+len(s))
	b[0] = stream
	binary.BigEndian.PutUint32(b[4:], uint32(len(s)))
	return append(b, s...)
}

func TestHTTP_PingAndVersionNegotiation(t *testing.T) {
	f := &fakeEngine{running: true}
	c := newEngine(t, f)
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if ok, err := c.Running(context.Background(), "x"); err != nil || !ok {
			t.Fatalf("Running = %v, %v", ok, err)
		}
	}
	got := f.seen()
	want := []string{"/_ping", "/v1.45/containers/x/json", "/v1.45/containers/x/json"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("requests = %v, want %v", got, want)
	}
}

func TestHTTP_VersionFallback(t *testing.T) {
	f := &fakeEngine{noVer: true}
	c := newEngine(t, f)
	if _, err := c.Running(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	if got := f.seen(); got[1] != "/v1.44/containers/x/json" {
		t.Fatalf("requests = %v", got)
	}
}

func TestHTTP_PingDown(t *testing.T) {
	c := &Client{Host: "tcp://127.0.0.1:1"}
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("want error")
	}
}

func TestHTTP_NotFound(t *testing.T) {
	c := newEngine(t, &fakeEngine{})
	ctx := context.Background()
	if ok, err := c.Exists(ctx, "ghost"); ok || err != nil {
		t.Fatalf("Exists = %v, %v", ok, err)
	}
	if ok, err := c.Running(ctx, "ghost"); ok || err != nil {
		t.Fatalf("Running = %v, %v", ok, err)
	}
	if ok, err := c.Exists(ctx, "real"); !ok || err != nil {
		t.Fatalf("Exists(real) = %v, %v", ok, err)
	}
	_, err := c.StartedAt(ctx, "ghost")
	if err == nil || !strings.Contains(err.Error(), "No such container: ghost") {
		t.Fatalf("StartedAt err = %v, want engine message", err)
	}
}

func TestHTTP_Times(t *testing.T) {
	c := newEngine(t, &fakeEngine{})
	st, err := c.StartedAt(context.Background(), "x")
	if want := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC); err != nil || !st.Equal(want) {
		t.Fatalf("StartedAt = %v, %v", st, err)
	}
	fin, err := c.FinishedAt(context.Background(), "x")
	if err != nil || !fin.IsZero() {
		t.Fatalf("FinishedAt = %v, %v, want zero", fin, err)
	}
}

func TestHTTP_UnixSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("unix sockets unavailable:", err)
	}
	srv := &http.Server{Handler: &fakeEngine{running: true}}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	c := &Client{Host: "unix://" + sock}
	if ok, err := c.Running(context.Background(), "x"); err != nil || !ok {
		t.Fatalf("Running = %v, %v", ok, err)
	}
	// Empty Host falls back to DOCKER_HOST.
	t.Setenv("DOCKER_HOST", "unix://"+sock)
	c2 := &Client{}
	if err := c2.Ping(context.Background()); err != nil {
		t.Fatalf("Ping via DOCKER_HOST: %v", err)
	}
}

func TestHTTP_TLSFallsBackToCLI(t *testing.T) {
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	c, _ := newFakeDocker(t, "#!/bin/sh\necho 29.0.0\n")
	c.Host = "tcp://somewhere:2376"
	if !c.useCLI() {
		t.Fatal("useCLI = false with TLS env and tcp host")
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping via CLI: %v", err)
	}
}

func readLogs(t *testing.T, rc io.ReadCloser, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(rc, buf); err != nil {
		t.Fatalf("read logs: %v", err)
	}
	return string(buf)
}

func TestHTTP_LogsMultiplexed(t *testing.T) {
	var body []byte
	body = append(body, frame(1, "hello ")...)
	body = append(body, frame(2, "err\n")...)
	f := &fakeEngine{logBody: body}
	c := newEngine(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rc, err := c.Logs(ctx, "x", "10m", "50")
	if err != nil {
		t.Fatal(err)
	}
	if got := readLogs(t, rc, 10); got != "hello err\n" {
		t.Fatalf("logs = %q", got)
	}
	done := make(chan struct{})
	go func() { rc.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return")
	}
	uris := f.seen()
	last := uris[len(uris)-1]
	for _, w := range []string{"follow=1", "stdout=1", "stderr=1", "tail=50", "since="} {
		if !strings.Contains(last, w) {
			t.Errorf("logs URI %q missing %q", last, w)
		}
	}
}

func TestHTTP_LogsTTY(t *testing.T) {
	c := newEngine(t, &fakeEngine{tty: true, logBody: []byte("raw tty\n")})
	ctx, cancel := context.WithCancel(context.Background())
	rc, err := c.Logs(ctx, "x", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if got := readLogs(t, rc, 8); got != "raw tty\n" {
		t.Fatalf("logs = %q", got)
	}
	cancel()
	if _, err := io.ReadAll(rc); err == nil {
		t.Fatal("read after cancel should error")
	}
}

func TestHTTP_LogsMissingAndBadSince(t *testing.T) {
	c := newEngine(t, &fakeEngine{})
	if _, err := c.Logs(context.Background(), "ghost", "", ""); err == nil || !strings.Contains(err.Error(), "No such container") {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.Logs(context.Background(), "x", "banana", ""); err == nil {
		t.Fatal("want error for bad since")
	}
}

func TestSinceParam(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cases := map[string]string{
		"1h":                        fmt.Sprintf("%d.000000000", now.Add(-time.Hour).Unix()),
		"2026-01-01T11:00:00Z":      fmt.Sprintf("%d.000000000", now.Add(-time.Hour).Unix()),
		"2026-01-01T11:00:00.5Z":    fmt.Sprintf("%d.500000000", now.Add(-time.Hour).Unix()),
		"1700000000":                "1700000000",
		"2026-01-01T13:00:00+02:00": fmt.Sprintf("%d.000000000", now.Add(-time.Hour).Unix()),
	}
	for in, want := range cases {
		got, err := sinceParam(in, now)
		if err != nil || got != want {
			t.Errorf("sinceParam(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestBytesSize(t *testing.T) {
	cases := map[float64]string{
		0:                 "0B",
		512 << 20:         "512MiB",
		1.204 * (1 << 30): "1.204GiB",
		13.62 * (1 << 30): "13.62GiB",
		1023:              "1023B",
		5 * (1 << 40):     "5TiB",
	}
	for in, want := range cases {
		if got := bytesSize(in); got != want {
			t.Errorf("bytesSize(%v) = %q, want %q", in, got, want)
		}
	}
}

func statsBody(id string, total, system uint64, preTotal, preSystem uint64, usage, inactive, limit uint64) string {
	return fmt.Sprintf(`{"id":%q,"cpu_stats":{"cpu_usage":{"total_usage":%d},"system_cpu_usage":%d,"online_cpus":4},
"precpu_stats":{"cpu_usage":{"total_usage":%d},"system_cpu_usage":%d,"online_cpus":4},
"memory_stats":{"usage":%d,"limit":%d,"stats":{"inactive_file":%d}}}`,
		id, total, system, preTotal, preSystem, usage, limit, inactive)
}

func TestHTTP_StatsSlowThenCached(t *testing.T) {
	const gi = 1 << 30
	f := &fakeEngine{stats: []string{
		// slow path: precpu populated. cpu = 100/1000*4*100 = 40%
		statsBody("abc", 1100, 11000, 1000, 10000, 3*gi, 1*gi, 16*gi),
		// one-shot: precpu empty; delta vs cached (1100,11000): 50/500*4*100 = 40... use 25/1000 -> 10%
		statsBody("abc", 1125, 12000, 0, 0, 2*gi, 0, 16*gi),
		// counters went backwards (restart): must use slow path next
		statsBody("abc", 10, 100, 0, 0, 2*gi, 0, 16*gi),
		statsBody("abc", 20, 200, 10, 100, 2*gi, 0, 16*gi),
	}}
	c := newEngine(t, f)
	ctx := context.Background()

	s, err := c.Stats(ctx, "x")
	if err != nil {
		t.Fatal(err)
	}
	want := Stats{CPUPercent: "40.00", MemUsed: "2GiB", MemTotal: "16GiB", MemPercent: "12.50", MemUsedBytes: 2 << 30}
	if s != want {
		t.Fatalf("slow Stats = %+v, want %+v", s, want)
	}

	s, err = c.Stats(ctx, "x")
	if err != nil {
		t.Fatal(err)
	}
	want = Stats{CPUPercent: "10.00", MemUsed: "2GiB", MemTotal: "16GiB", MemPercent: "12.50", MemUsedBytes: 2 << 30}
	if s != want {
		t.Fatalf("cached Stats = %+v, want %+v", s, want)
	}

	// Third body regressed -> falls through to the 4th body (slow path).
	s, err = c.Stats(ctx, "x")
	if err != nil {
		t.Fatal(err)
	}
	if s.CPUPercent != "40.00" {
		t.Fatalf("after regress CPUPercent = %s, want 40.00 from precpu", s.CPUPercent)
	}

	var oneShot, slow int
	for _, u := range f.seen() {
		if !strings.Contains(u, "/stats") {
			continue
		}
		if strings.Contains(u, "one-shot=true") {
			oneShot++
		} else if strings.Contains(u, "stream=false") {
			slow++
		}
	}
	if oneShot != 2 || slow != 2 {
		t.Fatalf("oneShot=%d slow=%d, want 2 and 2 (%v)", oneShot, slow, f.seen())
	}
}

func TestHTTP_StatsStaleSampleDiscarded(t *testing.T) {
	f := &fakeEngine{stats: []string{statsBody("abc", 1100, 11000, 1000, 10000, 1<<30, 0, 2<<30)}}
	c := newEngine(t, f)
	c.samples = map[string]cpuSample{"x": {id: "abc", total: 1, system: 1, at: time.Now().Add(-2 * sampleMaxAge)}}
	if _, err := c.Stats(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	for _, u := range f.seen() {
		if strings.Contains(u, "one-shot") {
			t.Fatalf("stale sample used one-shot: %v", f.seen())
		}
	}
}

func TestMemUsed_CgroupV1(t *testing.T) {
	if got := memUsed(100, map[string]uint64{"total_inactive_file": 30}); got != 70 {
		t.Fatalf("got %d", got)
	}
}
