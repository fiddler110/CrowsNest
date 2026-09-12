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

// handleLogs streams `docker logs -f` for a game as Server-Sent Events,
// formatted through the game's LogLineFormatter (plain pass-through if none
// is set) — direct equivalent of the original Python CrowsNest's /api/logs.
func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	d, ok := a.gameOr404(w, r)
	if !ok {
		return
	}

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
// Windrose, for now — see docs/implementation-plan.md phase 7) emit a
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

	// tail=all so a client that subscribes after the milestone line already
	// scrolled past still sees it replayed, not just newly-written lines.
	rc, err := a.Docker.Logs(r.Context(), d.ContainerName, "", "all")
	if err != nil {
		sw.WriteEvent("error", err.Error())
		return
	}
	defer rc.Close()

	best := -1
	streamLines(r, sw, rc, a.keepaliveInterval(), func(line string) (event, text string, emit bool) {
		for i, m := range d.Startup.Milestones {
			if i <= best {
				continue
			}
			if m.Pattern.MatchString(line) {
				best = i
				body, _ := json.Marshal(progressEvent{Pct: m.Pct, Label: m.Label})
				return "progress", string(body), true
			}
		}
		return "", "", false
	})
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
