// Package dockertest is a small fake of the Docker Engine API for tests: containers that start and stop, exec with
// scripted output, logs, and a switch that makes the daemon "go down". Client() returns a dockerctl.Client talking to
// it over TCP, the way the panel talks to the guard.
package dockertest

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/dockerctl"
)

// Container is one fake container.
type Container struct {
	Running   bool
	StartedAt time.Time
	Image     string
	// Finished, when set, is when the container last stopped (reported while it is down, or after a restart).
	Finished time.Time
}

// ExecFunc answers an exec: what the command printed and its exit code. stdin is what the caller wrote.
type ExecFunc func(container string, cmd []string, stdin string) (stdout, stderr string, code int)

// Fake is the engine.
type Fake struct {
	// Exec answers every exec; nil means success with no output.
	Exec ExecFunc
	// OnStart and OnStop, when set, run before a start or stop is applied. They may block (they get the request's
	// context, which ends when the client gives up) and may refuse with a status and message (0 means go ahead).
	OnStart, OnStop func(ctx context.Context, name string) (status int, msg string)
	// Stats is the body of a container stats call; empty means a stopped-looking 404-free default of zeros.
	Stats string
	// Delay holds every request this long (or until the client gives up): a daemon that hangs.
	Delay time.Duration
	// LogsFunc, when set, answers a logs call instead of Logs; query is the request's (since, tail, follow).
	LogsFunc func(name string, query url.Values) string
	// Logs is what `logs` returns per container (as stdout).
	Logs map[string]string

	mu         sync.Mutex
	containers map[string]*Container
	calls      []string
	down       bool
	failStart  map[string]int
	stuck      map[string]bool
	execs      map[string]execRec
	nextExec   int
	srv        *httptest.Server
}

type execRec struct {
	container string
	cmd       []string
	stdin     bool
	code      int
}

// New starts a fake engine that is shut down with the test.
func New(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{containers: map[string]*Container{}, Logs: map[string]string{}, failStart: map[string]int{}, stuck: map[string]bool{}, execs: map[string]execRec{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// Client is a dockerctl client for the fake.
func (f *Fake) Client() *dockerctl.Client {
	return &dockerctl.Client{Host: "tcp://" + strings.TrimPrefix(f.srv.URL, "http://")}
}

// Handler is the engine's HTTP handler, for a test that serves some paths itself and hands the rest on.
func (f *Fake) Handler() http.Handler { return http.HandlerFunc(f.serve) }

// Add creates a container (running or stopped).
func (f *Fake) Add(name string, running bool) *Container {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := &Container{Running: running, StartedAt: time.Now().UTC()}
	f.containers[name] = c
	return c
}

// Remove deletes a container.
func (f *Fake) Remove(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.containers, name)
}

// SetRunning flips a container's state.
func (f *Fake) SetRunning(name string, running bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.containers[name]; c != nil {
		c.Running = running
	}
}

// SetStartedAt sets a container's start time.
func (f *Fake) SetStartedAt(name string, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.containers[name]; c != nil {
		c.StartedAt = at
	}
}

// Running reports whether the container exists and is running.
func (f *Fake) Running(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.containers[name]
	return c != nil && c.Running
}

// Down makes every request fail with 500 (a daemon or proxy hiccup).
func (f *Fake) Down(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

// FailStart makes starting name answer with status (0 clears it).
func (f *Fake) FailStart(name string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failStart[name] = status
}

// Stuck makes name ignore stop requests (it answers them but stays up), like a game that will not shut down.
func (f *Fake) Stuck(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stuck[name] = true
}

// Calls is every request seen, as "POST /containers/x/start" (versions stripped), oldest first.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// Count is how many calls have exactly this text.
func (f *Fake) Count(call string) int {
	n := 0
	for _, c := range f.Calls() {
		if c == call {
			n++
		}
	}
	return n
}

var versionRe = regexp.MustCompile(`^/v[0-9.]+`)

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	path := versionRe.ReplaceAllString(r.URL.Path, "")
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+path)
	down := f.down
	f.mu.Unlock()
	if f.Delay > 0 {
		select {
		case <-time.After(f.Delay):
		case <-r.Context().Done():
			return
		}
	}
	if path == "/_ping" && !down {
		w.Header().Set("API-Version", "1.45")
		fmt.Fprint(w, "OK")
		return
	}
	if down {
		http.Error(w, `{"message":"the daemon is down"}`, http.StatusInternalServerError)
		return
	}
	switch {
	case strings.HasPrefix(path, "/exec/") && strings.HasSuffix(path, "/start"):
		f.execStart(w, r, strings.TrimSuffix(strings.TrimPrefix(path, "/exec/"), "/start"))
	case strings.HasPrefix(path, "/exec/") && strings.HasSuffix(path, "/json"):
		f.mu.Lock()
		e := f.execs[strings.TrimSuffix(strings.TrimPrefix(path, "/exec/"), "/json")]
		f.mu.Unlock()
		writeJSON(w, map[string]any{"Running": false, "ExitCode": e.code})
	case strings.HasPrefix(path, "/containers/"):
		rest := strings.TrimPrefix(path, "/containers/")
		name, action, _ := strings.Cut(rest, "/")
		f.container(w, r, name, action)
	default:
		http.NotFound(w, r)
	}
}

func notFound(w http.ResponseWriter, name string) {
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, `{"message":"No such container: %s"}`, name)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *Fake) container(w http.ResponseWriter, r *http.Request, name, action string) {
	f.mu.Lock()
	c := f.containers[name]
	status := f.failStart[name]
	f.mu.Unlock()
	if c == nil && !(name == "create" && r.Method == http.MethodPost) {
		notFound(w, name)
		return
	}
	switch {
	case action == "json" || (action == "" && r.Method == http.MethodGet):
		f.mu.Lock()
		running, started := c.Running, c.StartedAt
		f.mu.Unlock()
		finished := "0001-01-01T00:00:00Z"
		f.mu.Lock()
		fin := c.Finished
		f.mu.Unlock()
		if !fin.IsZero() {
			finished = fin.UTC().Format(time.RFC3339Nano)
		}
		writeJSON(w, map[string]any{"Id": "abc", "State": map[string]any{"Running": running, "StartedAt": started.Format(time.RFC3339Nano), "FinishedAt": finished},
			"Config": map[string]any{"Tty": false, "Image": c.Image}})
	case action == "start" && r.Method == http.MethodPost:
		if f.OnStart != nil {
			if st, msg := f.OnStart(r.Context(), name); st != 0 {
				w.WriteHeader(st)
				writeJSON(w, map[string]string{"message": msg})
				return
			}
		}
		if status != 0 {
			w.WriteHeader(status)
			fmt.Fprint(w, `{"message":"start refused"}`)
			return
		}
		f.mu.Lock()
		if !c.Running {
			c.Running, c.StartedAt = true, time.Now().UTC()
		}
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case action == "stop" && r.Method == http.MethodPost:
		if f.OnStop != nil {
			if st, msg := f.OnStop(r.Context(), name); st != 0 {
				w.WriteHeader(st)
				writeJSON(w, map[string]string{"message": msg})
				return
			}
		}
		f.mu.Lock()
		if !f.stuck[name] {
			c.Running, c.Finished = false, time.Now().UTC()
		}
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case action == "stats":
		body := f.Stats
		if body == "" {
			body = `{"id":"abc","cpu_stats":{"cpu_usage":{"total_usage":0},"system_cpu_usage":0,"online_cpus":1},"precpu_stats":{},"memory_stats":{"usage":0,"limit":0}}`
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	case action == "logs":
		f.mu.Lock()
		body := f.Logs[name]
		f.mu.Unlock()
		if f.LogsFunc != nil {
			body = f.LogsFunc(name, r.URL.Query())
		}
		for _, line := range strings.SplitAfter(body, "\n") {
			if line != "" {
				frame(w, 1, line)
			}
		}
	case action == "exec" && r.Method == http.MethodPost:
		var req struct {
			Cmd         []string
			AttachStdin bool
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.nextExec++
		id := fmt.Sprintf("exec%d", f.nextExec)
		f.execs[id] = execRec{container: name, cmd: req.Cmd, stdin: req.AttachStdin}
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]string{"Id": id})
	default:
		http.NotFound(w, r)
	}
}

func frame(w io.Writer, stream byte, s string) {
	var h [8]byte
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(s)))
	_, _ = w.Write(h[:])
	_, _ = io.WriteString(w, s)
}

// execStart hijacks the connection like the engine: 101, then framed output until the command ends. It reads stdin
// until the client half-closes, but only when the exec asked for it.
func (f *Fake) execStart(w http.ResponseWriter, r *http.Request, id string) {
	f.mu.Lock()
	e, ok := f.execs[id]
	f.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	_, _ = io.Copy(io.Discard, r.Body) // the start request's JSON, before the stream begins
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", 500)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = brw.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	_ = brw.Flush()
	var stdin strings.Builder
	if e.stdin { // read until the client half-closes
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
		}
		b, _ := io.ReadAll(brw)
		stdin.Write(b)
	}
	var out, errOut string
	code := 0
	if f.Exec != nil {
		out, errOut, code = f.Exec(e.container, e.cmd, stdin.String())
	}
	f.mu.Lock()
	e.code = code
	f.execs[id] = e
	f.mu.Unlock()
	if out != "" {
		frame(conn, 1, out)
	}
	if errOut != "" {
		frame(conn, 2, errOut)
	}
}
