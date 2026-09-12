package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
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
