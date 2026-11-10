package web

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/settings"
)

// pagesHarness has two games: "rich" (info, console, accent) and "plain".
func pagesHarness(t *testing.T) *testHarness {
	t.Helper()
	docker := fakeDockerClient(t, "#!/bin/sh\nexit 0\n")
	h := newHarnessFromDefs(t, docker, []games.GameDef{
		{ID: "rich", DisplayName: "Rich", ContainerName: "rich", Status: &games.DockerStatusChecker{Docker: docker},
			Info: fakeInfoProvider{ok: true}, Console: &fakeConsole{}, Accent: "#60a5fa"},
		{ID: "plain", DisplayName: "Plain", ContainerName: "plain", Status: &games.DockerStatusChecker{Docker: docker}},
	})
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RoleAdmin}}
	return h
}

func (h *testHarness) get(t *testing.T, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

// cardOf returns the rendered <article> of one game card.
func cardOf(t *testing.T, body, id string) string {
	t.Helper()
	start := strings.Index(body, `<article class="game-card" data-id="`+id+`"`)
	if start < 0 {
		t.Fatalf("no card for %s", id)
	}
	end := strings.Index(body[start:], "</article>")
	return body[start : start+end]
}

func TestDashboard_InfoTabOnlyWithInfoProvider(t *testing.T) {
	h := pagesHarness(t)
	body := h.get(t, "/")
	rich, plain := cardOf(t, body, "rich"), cardOf(t, body, "plain")
	if !strings.Contains(rich, `data-tab="info"`) || !strings.Contains(rich, `data-panel="info"`) {
		t.Error("game with an info provider has no Info tab")
	}
	if strings.Contains(plain, `data-tab="info"`) || strings.Contains(plain, `data-panel="info"`) {
		t.Error("game without an info provider shows an Info tab")
	}
	if !strings.Contains(rich, `data-accent="#60a5fa"`) || strings.Contains(plain, "data-accent") {
		t.Error("accent is not carried to (only) the card that has one")
	}
	if !strings.Contains(rich, `role="tablist"`) || !strings.Contains(rich, `aria-controls="panel-rich-console"`) {
		t.Error("card panels are not a tab group")
	}
}

var (
	idAttr      = regexp.MustCompile(`\sid="([^"]+)"`)
	unversioned = regexp.MustCompile(`"/static/[^"?]*"`)
)

// Every page, as rendered, has unique ids, the shared top bar with the right
// entry marked, Log out, and hashed asset URLs only.
func TestPages_SharedLayoutAndUniqueIDs(t *testing.T) {
	h := pagesHarness(t)
	for _, tc := range []struct{ path, current string }{
		{"/", "dashboard-btn"}, {"/games", "games-btn"}, {"/settings", "settings-btn"}, {"/login", ""},
	} {
		body := h.get(t, tc.path)
		seen := map[string]bool{}
		for _, m := range idAttr.FindAllStringSubmatch(body, -1) {
			if seen[m[1]] {
				t.Errorf("%s: duplicate id %q", tc.path, m[1])
			}
			seen[m[1]] = true
		}
		if unversioned.MatchString(body) {
			t.Errorf("%s: an unversioned /static URL is left in the page", tc.path)
		}
		if tc.current == "" {
			continue
		}
		if !seen["logout-btn"] || strings.Count(body, "<symbol ") == 0 || !seen["confirm-dialog"] || !seen["toasts"] {
			t.Errorf("%s: missing the shared top bar, sprite or chrome", tc.path)
		}
		if n := strings.Count(body, `aria-current="page"`); n != 1 || !regexp.MustCompile(`id="`+tc.current+`"[^>]*aria-current="page"`).MatchString(body) {
			t.Errorf("%s: want only %s marked current (%d marked)", tc.path, tc.current, n)
		}
		if !strings.Contains(body, "/static/api.js?v=") {
			t.Errorf("%s: api.js is not loaded", tc.path)
		}
	}
}

// The no-duplicate-ids check also runs over the template sources (with the
// layout), so a duplicate inside a branch the render above did not take is
// caught too. Ids built from template actions are skipped.
func TestTemplates_NoDuplicateIDs(t *testing.T) {
	layout, err := fs.ReadFile(templateFS, layoutFile)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pages {
		if p == layoutFile {
			continue
		}
		src, err := fs.ReadFile(templateFS, p)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, m := range idAttr.FindAllStringSubmatch(string(src)+string(layout), -1) {
			if strings.Contains(m[1], "{{") {
				continue
			}
			if seen[m[1]] {
				t.Errorf("%s: duplicate id %q", p, m[1])
			}
			seen[m[1]] = true
		}
	}
}

func TestEmptyDashboard_AdminsGetTheGamesPage(t *testing.T) {
	h := newHarnessFromDefs(t, fakeDockerClient(t, "#!/bin/sh\nexit 0\n"), nil)
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RoleAdmin}}
	if body := h.get(t, "/"); !strings.Contains(body, `<a href="/games">`) || strings.Contains(body, "config.yaml") {
		t.Error("an admin's empty dashboard should point at the Games page")
	}
	h.App.Auth.Sessions.Users = auth.Users{"tester": {Role: auth.RolePlayer}}
	if body := h.get(t, "/"); strings.Contains(body, `href="/games"`) {
		t.Error("a player's empty dashboard links to the admin-only Games page")
	}
}

var assetURL = regexp.MustCompile(`/static/app\.js\?v=([0-9a-f]+)`)

func TestStaticAssets_HashedCachedAndGzipped(t *testing.T) {
	h := pagesHarness(t)
	m := assetURL.FindStringSubmatch(h.get(t, "/"))
	if m == nil {
		t.Fatal("dashboard does not reference a hashed app.js")
	}
	want, err := fs.ReadFile(staticFS, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(path string, hdr map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, r)
		return rec
	}

	rec := fetch(m[0], map[string]string{"Accept-Encoding": "br, gzip"})
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("versioned app.js = %d, encoding %q", rec.Code, rec.Header().Get("Content-Encoding"))
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") || !strings.Contains(cc, "max-age=31536000") {
		t.Errorf("versioned Cache-Control = %q", cc)
	}
	if rec.Header().Get("Vary") != "Accept-Encoding" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/javascript") {
		t.Errorf("headers = %v", rec.Header())
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(zr)
	if !bytes.Equal(got, want) {
		t.Error("gzipped body is not app.js")
	}
	etag := rec.Header().Get("ETag")

	rec = fetch(m[0], nil)
	if rec.Header().Get("Content-Encoding") != "" || !bytes.Equal(rec.Body.Bytes(), want) {
		t.Error("a client without gzip should get the plain file")
	}
	if rec = fetch(m[0], map[string]string{"Accept-Encoding": "gzip;q=0"}); rec.Header().Get("Content-Encoding") != "" {
		t.Error("gzip;q=0 should refuse gzip")
	}

	for _, path := range []string{"/static/app.js", "/static/app.js?v=stale"} {
		if cc := fetch(path, nil).Header().Get("Cache-Control"); strings.Contains(cc, "immutable") || !strings.Contains(cc, "max-age=3600") {
			t.Errorf("%s Cache-Control = %q, want a short max-age", path, cc)
		}
	}

	if rec = fetch(m[0], map[string]string{"Accept-Encoding": "gzip", "If-None-Match": etag}); rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
		t.Errorf("If-None-Match = %d, want 304", rec.Code)
	}

	rec = fetch("/static/texture.jpg", map[string]string{"Accept-Encoding": "gzip"})
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Encoding") != "" || rec.Header().Get("Content-Type") != "image/jpeg" || rec.Header().Get("Cache-Control") == "" {
		t.Errorf("image: %d %v", rec.Code, rec.Header())
	}
	if rec = fetch("/static/nope.js", nil); rec.Code != http.StatusNotFound {
		t.Errorf("missing asset = %d", rec.Code)
	}
}

func TestAcceptsGzip(t *testing.T) {
	for header, want := range map[string]bool{
		"": false, "gzip": true, "deflate, gzip;q=0.5": true, "gzip;q=0": false, "GZIP": true,
		"*": true, "*;q=0, gzip": true, "gzip;q=0, *": false, "br": false, "identity": false,
	} {
		if got := acceptsGzip(header); got != want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", header, got, want)
		}
	}
}

func TestGetSettings_IncludesTimeZoneButPutRefusesIt(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	store, err := settings.New(settings.Values{IdleMinutes: 15, NightStartHour: 23, NightEndHour: 5, MaxActiveGames: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	h.App.Settings = store
	h.App.TimeZone = "Europe/London"

	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.req(http.MethodGet, "/api/settings", nil))
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("GET = %d %s", rec.Code, rec.Body)
	}
	if got["tz"] != "Europe/London" || got["idle_minutes"] != float64(15) {
		t.Fatalf("GET body = %v", got)
	}

	// The page sends back only the settings fields; tz is not one of them.
	rec = httptest.NewRecorder()
	h.mux().ServeHTTP(rec, h.authedReq(http.MethodPut, "/api/settings", []byte(`{"idle_minutes":20,"tz":"UTC"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("PUT with tz = %d, want 400", rec.Code)
	}
}
