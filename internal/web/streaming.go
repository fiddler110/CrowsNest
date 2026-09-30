package web

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/sse"
)

// logKeepaliveInterval and startupKeepaliveInterval bound how long an SSE
// connection can sit idle before a comment line is sent to keep proxies and
// the client from timing it out. Tests override these via App fields.
const defaultKeepaliveInterval = 15 * time.Second

func (a *App) keepaliveInterval() time.Duration {
	if a.KeepaliveInterval > 0 {
		return a.KeepaliveInterval
	}
	return defaultKeepaliveInterval
}

// defaultMaxConcurrentStreams bounds how many `docker logs -f` subprocesses
// handleLogs/handleStartupProgress may have open at once, across all games
// combined. Each open SSE connection holds one for as long as the client
// stays connected, so with no cap a handful of forgotten browser tabs (or a
// client that doesn't close streams) can accumulate unboundedly.
const defaultMaxConcurrentStreams = 20

func (a *App) maxConcurrentStreams() int {
	if a.MaxConcurrentStreams > 0 {
		return a.MaxConcurrentStreams
	}
	return defaultMaxConcurrentStreams
}

// acquireStream reserves a slot for a new log-streaming subprocess,
// reporting false if the process-wide cap is already reached.
func (a *App) acquireStream() bool {
	for {
		cur := a.streamCount.Load()
		if int(cur) >= a.maxConcurrentStreams() {
			return false
		}
		if a.streamCount.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (a *App) releaseStream() {
	a.streamCount.Add(-1)
}

// handleLogs streams `docker logs -f` for a game as Server-Sent Events,
// formatted through the game's LogLineFormatter (plain pass-through if none
// is set) — direct equivalent of the original Python CrowsNest's /api/logs.
func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}
	if !a.acquireStream() {
		http.Error(w, "too many active log streams, try again shortly", http.StatusServiceUnavailable)
		return
	}
	defer a.releaseStream()

	tail := r.URL.Query().Get("tail")
	if tail == "" {
		tail = "200"
	}
	if tail != "all" {
		if _, err := strconv.Atoi(tail); err != nil {
			tail = "200"
		}
	}

	rc, err := a.Docker.Logs(r.Context(), d.ContainerName, "", tail)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer rc.Close()

	sw, ok := sse.NewWriter(w)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	formatter := d.LogFormatter
	if formatter == nil {
		formatter = games.PassthroughFormatter{}
	}

	streamLines(r, sw, rc, a.keepaliveInterval(), func(line string) (event, text string, emit bool) {
		event, text = formatter.Format(line)
		return event, text, true
	})
}

type progressEvent struct {
	Pct   int    `json:"pct"`
	Label string `json:"label"`
}

// handleStartupProgress streams startup-milestone matches for a game as
// Server-Sent Events. Games without a StartupMatcher (everything but
// Windrose and Palworld, for now) emit a
// single "unsupported" event and close; the dashboard treats that as "no
// progress bar for this game."
func (a *App) handleStartupProgress(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}

	sw, ok := sse.NewWriter(w)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	if d.Startup == nil || len(d.Startup.Milestones) == 0 {
		sw.WriteEvent("unsupported", "this game has no startup progress tracking")
		return
	}

	if !a.acquireStream() {
		sw.WriteEvent("error", "too many active log streams, try again shortly")
		return
	}
	defer a.releaseStream()

	// Read only the current run's log: a container restarted by compose keeps
	// its earlier runs' output, and replaying a previous run's "ready" line
	// would report 100% before the new run has even begun. tail=all so a
	// client that subscribes after a milestone already scrolled past still
	// sees it replayed. If StartedAt can't be read, fall back to the whole
	// log rather than fail the stream.
	since := ""
	if started, err := a.Docker.StartedAt(r.Context(), d.ContainerName); err == nil {
		since = started.UTC().Format(time.RFC3339Nano)
	}
	rc, err := a.Docker.Logs(r.Context(), d.ContainerName, since, "all")
	if err != nil {
		sw.WriteEvent("error", err.Error())
		return
	}
	defer rc.Close()

	// Progress only moves forward: log lines can repeat or arrive out of
	// order relative to the milestone table.
	last := -1
	streamLines(r, sw, rc, a.keepaliveInterval(), func(line string) (event, text string, emit bool) {
		pct, label, ok := matchStartup(d.Startup, line)
		if !ok || pct <= last {
			return "", "", false
		}
		last = pct
		body, _ := json.Marshal(progressEvent{Pct: pct, Label: label})
		return "progress", string(body), true
	})
}

// matchStartup returns the progress a log line represents, if any: Parse
// first (values read from the line), then the first matching milestone.
func matchStartup(m *games.StartupMatcher, line string) (pct int, label string, ok bool) {
	if m.Parse != nil {
		if pct, label, ok = m.Parse(line); ok {
			return pct, label, true
		}
	}
	for _, ms := range m.Milestones {
		if ms.Pattern.MatchString(line) {
			return ms.Pct, ms.Label, true
		}
	}
	return 0, "", false
}

// streamLines reads newline-delimited text from rc, and for each line whose
// onLine callback returns a non-empty event or text, writes it as an SSE
// event. It also sends periodic keepalive comments, and returns as soon as
// the request context is cancelled (client disconnect) or rc reaches EOF.
func streamLines(r *http.Request, sw *sse.Writer, rc interface{ Read([]byte) (int, error) }, keepalive time.Duration, onLine func(line string) (event, text string, emit bool)) {
	ctx := r.Context()

	lines := make(chan string)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(rc)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			lines <- strings.TrimSuffix(scanner.Text(), "\r")
		}
	}()

	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-lines:
			if !ok {
				return
			}
			event, text, emit := onLine(line)
			if !emit {
				continue
			}
			if err := sw.WriteEvent(event, text); err != nil {
				return
			}
		case <-ticker.C:
			if err := sw.WriteComment("keepalive"); err != nil {
				return
			}
		}
	}
}
