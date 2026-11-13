package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeCrashes struct{}

func (fakeCrashes) Total(id string) uint64 {
	if id == "windrose" {
		return 2
	}
	return 0
}
func (fakeCrashes) Looping(id string) bool { return id == "windrose" }

func TestMetrics_TokenGatedAndExposesGames(t *testing.T) {
	h := newHarness(t, nil, "windrose")
	h.App.HostPaths = []string{t.TempDir()}

	// No token configured: the route does not exist.
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code == http.StatusOK || rec.Code == http.StatusUnauthorized {
		t.Fatalf("/metrics without a token configured = %d, want it absent", rec.Code)
	}

	h.App.MetricsToken = "s3cret"
	h.App.Crashes = fakeCrashes{}
	get := func(auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, req)
		return rec
	}
	for _, bad := range []string{"", "Bearer nope", "s3cret", "Basic s3cret"} {
		if rec := get(bad); rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q = %d, want 401", bad, rec.Code)
		}
	}
	rec = get("Bearer s3cret")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("authorised = %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	for _, want := range []string{
		"# TYPE crowsnest_game_up gauge", `crowsnest_game_up{game="windrose"} 0`,
		`crowsnest_game_crashes_total{game="windrose"} 2`, `crowsnest_game_crash_looping{game="windrose"} 1`,
		"crowsnest_host_memory_available_bytes ", "crowsnest_host_disk_free_bytes{path=",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q in:\n%s", want, body)
		}
	}
}
