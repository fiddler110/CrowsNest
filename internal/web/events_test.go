package web

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
)

// A failed start leaves an error whose raw detail only admins may see.
const failedStartScript = "#!/bin/sh\ncase \"$1\" in ps) if [ \"$2\" = \"-a\" ]; then echo windrose; fi ;; start) echo 'boom: secret path' >&2; exit 1 ;; stop) sleep 0.5 ;; esac\n"

type eventReader struct {
	t  *testing.T
	sc *bufio.Scanner
}

// next returns the next event's name and data, skipping comments.
func (er eventReader) next() (event, data string) {
	er.t.Helper()
	for er.sc.Scan() {
		line := er.sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		case line == "" && event != "":
			return event, data
		}
	}
	er.t.Fatalf("stream ended: %v", er.sc.Err())
	return "", ""
}

// openEvents connects to /api/events as role and returns a reader and the
// cancel that disconnects.
func openEvents(t *testing.T, role auth.Role) (*testHarness, eventReader, context.CancelFunc) {
	t.Helper()
	h := newHarness(t, failedStartScript)
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: role}}
	h.App.EventsMinGap = 10 * time.Millisecond
	if err := h.App.Exclusivity.RequestStart(context.Background(), "windrose"); err != nil {
		t.Fatal(err)
	}
	h.App.Exclusivity.Wait()
	srv := httptest.NewServer(h.mux())
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/events", nil)
	req.AddCookie(h.Cookie)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("GET /api/events = %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	return h, eventReader{t, bufio.NewScanner(res.Body)}, cancel
}

func TestEvents_GamesAreRoleFiltered(t *testing.T) {
	_, er, _ := openEvents(t, auth.RolePlayer)
	ev, data := er.next()
	if ev != "games" || !strings.Contains(data, `"start_error"`) || strings.Contains(data, "boom") {
		t.Fatalf("player's first event = %s %s, want games with the public error only", ev, data)
	}
	if ev, data := er.next(); ev != "health" || !strings.Contains(data, `"docker"`) {
		t.Fatalf("second event = %s %s, want health", ev, data)
	}

	_, er, _ = openEvents(t, auth.RoleAdmin)
	if ev, data := er.next(); ev != "games" || !strings.Contains(data, "boom: secret path") {
		t.Fatalf("admin's first event = %s %s, want games with the detail", ev, data)
	}
}

// A transition is pushed without the client asking, and the handler exits
// once the client goes away.
func TestEvents_PushesChangesAndStopsOnDisconnect(t *testing.T) {
	h, er, cancel := openEvents(t, auth.RoleAdmin)
	er.next() // games
	er.next() // health
	if err := h.App.Exclusivity.RequestStop(context.Background(), "windrose"); err != nil {
		t.Fatal(err)
	}
	for {
		ev, data := er.next()
		if ev == "games" && strings.Contains(data, `"status":"stopping"`) {
			break
		}
	}
	h.App.Exclusivity.Wait()

	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		buf := make([]byte, 1<<20)
		buf = buf[:runtime.Stack(buf, true)]
		if !strings.Contains(string(buf), "handleEvents") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("events handler still running after disconnect:\n%s", buf)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := h.App.eventStreams.Load(); n != 0 {
		t.Fatalf("%d event streams still counted", n)
	}
}

func TestEvents_CapAndSession(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	h.App.MaxEventStreams = 1
	h.App.eventStreams.Store(1)
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req("GET", "/api/events", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("over the cap = %d, want 503", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest("GET", "/api/events", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("without a session = %d, want 401", rec.Code)
	}
}
