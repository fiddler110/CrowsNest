package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
)

const logsPrintTwoLines = `#!/bin/sh
case "$1" in
  logs) printf 'line one\nline two\n' ;;
esac
`

func TestHandleLogs_Passthrough(t *testing.T) {
	h := newHarness(t, logsPrintTwoLines)
	h.App.KeepaliveInterval = time.Hour

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/windrose/logs", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET logs = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "data: line one\n\n") {
		t.Fatalf("body missing first line, got: %q", body)
	}
	if !strings.Contains(body, "data: line two\n\n") {
		t.Fatalf("body missing second line, got: %q", body)
	}
	if strings.Contains(body, "event:") {
		t.Fatalf("passthrough lines should have no event: line, got: %q", body)
	}
}

func TestHandleLogs_StreamCapExceeded(t *testing.T) {
	h := newHarness(t, logsPrintTwoLines)
	h.App.MaxConcurrentStreams = 1
	h.App.streamCount.Store(1) // simulate one stream already in flight

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/windrose/logs", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET logs over the stream cap = %d, want %d, body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body)
	}
}

func TestHandleLogs_UnknownGame(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/palworld/logs", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET logs for unregistered game = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleLogs_Unauthenticated(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/games/windrose/logs", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET logs without a session = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleStartupProgress_Unsupported(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/windrose/startup-progress", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET startup-progress = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "event: unsupported") {
		t.Fatalf("body = %q, want an unsupported event for a game with no StartupMatcher", rec.Body.String())
	}
}

const logsPrintMilestoneLine = `#!/bin/sh
case "$1" in
  logs) printf 'booting...\nHost server is ready for owner to connect\n' ;;
esac
`

func TestHandleStartupProgress_MatchesMilestone(t *testing.T) {
	docker := fakeDockerClient(t, logsPrintMilestoneLine)
	defs := []games.GameDef{{
		ID:            "windrose",
		DisplayName:   "windrose",
		ContainerName: "windrose",
		Status:        &games.DockerStatusChecker{Docker: docker},
		Players:       games.UnknownPlayerCounter{},
		Startup: &games.StartupMatcher{
			Milestones: []games.Milestone{
				{Pattern: regexp.MustCompile("Host server is ready for owner to connect"), Pct: 100, Label: "Host server ready"},
			},
		},
	}}
	h := newHarnessFromDefs(t, docker, defs)
	h.App.KeepaliveInterval = time.Hour

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/windrose/startup-progress", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET startup-progress = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `event: progress`) {
		t.Fatalf("body missing progress event: %q", body)
	}
	if !strings.Contains(body, `"pct":100`) || !strings.Contains(body, `"label":"Host server ready"`) {
		t.Fatalf("body missing expected progress payload: %q", body)
	}
	if strings.Contains(body, "booting...") {
		t.Fatalf("non-matching lines should not be emitted as events: %q", body)
	}
}

// Fake docker for the progress tests below: `inspect` reports a StartedAt,
// and `logs` echoes its arguments to stderr-free stdout as a marker line so
// the test can see whether --since was passed, then prints download lines
// out of order to check progress only moves forward.
const logsDownloadWithStartedAt = `#!/bin/sh
case "$1" in
  inspect) echo 2026-09-30T13:00:00.123456789Z ;;
  logs) echo "ARGS: $*"; printf 'progress 40\nprogress 60\nprogress 50\nprogress 60\n' ;;
esac
`

func TestHandleStartupProgress_ParseIsMonotonicAndScopedToCurrentRun(t *testing.T) {
	docker := fakeDockerClient(t, logsDownloadWithStartedAt)
	re := regexp.MustCompile(`^progress (\d+)$`)
	defs := []games.GameDef{{
		ID:            "palworld",
		DisplayName:   "palworld",
		ContainerName: "palworld",
		Status:        &games.DockerStatusChecker{Docker: docker},
		Players:       games.UnknownPlayerCounter{},
		Startup: &games.StartupMatcher{
			Parse: func(line string) (int, string, bool) {
				m := re.FindStringSubmatch(line)
				if m == nil {
					return 0, "", false
				}
				n, _ := strconv.Atoi(m[1])
				return n, "downloading", true
			},
			Milestones: []games.Milestone{
				{Pattern: regexp.MustCompile(`ARGS: .*--since 2026-09-30T13:00:00\.123456789Z`), Pct: 5, Label: "scoped to current run"},
			},
		},
	}}
	h := newHarnessFromDefs(t, docker, defs)
	h.App.KeepaliveInterval = time.Hour

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/games/palworld/startup-progress", nil))
	body := rec.Body.String()

	if !strings.Contains(body, "scoped to current run") {
		t.Errorf("logs were not requested with --since <StartedAt>: %q", body)
	}
	if n := strings.Count(body, `"pct":60`); n != 1 {
		t.Errorf("pct 60 emitted %d times, want exactly once: %q", n, body)
	}
	if strings.Contains(body, `"pct":50`) {
		t.Errorf("progress moved backwards to 50: %q", body)
	}
	if !strings.Contains(body, `"pct":40`) {
		t.Errorf("missing first Parse-derived event: %q", body)
	}
}
