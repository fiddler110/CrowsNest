package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/auth"
	"github.com/fiddler110/crowsnest/internal/backup"
)

// profileHarness turns the registry on and signs the harness user in on two "devices".
func profileHarness(t *testing.T) (h *testHarness, other *http.Cookie, otherID string) {
	t.Helper()
	h = pagesHarness(t)
	reg, err := auth.NewSessionStore("")
	if err != nil {
		t.Fatal(err)
	}
	sm := h.App.Auth.Sessions
	sm.Registry = reg
	prof, _ := auth.NewProfileStore("")
	h.App.Profiles = prof
	mk := func(user, ua string) (auth.Session, *http.Cookie) {
		s, err := sm.New(user)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Add(auth.SessionRecord{ID: s.ID, User: user, Created: s.IssuedAt, LastSeen: s.IssuedAt, Expires: s.ExpiresAt, UserAgent: ua, IP: "10.0.0.9"}); err != nil {
			t.Fatal(err)
		}
		tok, _ := sm.Encode(s)
		return s, &http.Cookie{Name: auth.SessionCookieName, Value: tok}
	}
	cur, curCookie := mk("tester", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0")
	h.Cookie, h.CSRFToken = curCookie, cur.CSRFToken
	o, oc := mk("tester", "Mozilla/5.0 (iPhone; CPU iPhone OS 17) Safari/604.1")
	return h, oc, o.ID
}

func (h *testHarness) do(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.mux().ServeHTTP(rec, r)
	return rec
}

func TestProfile_ListsDevicesAndRevokesOne(t *testing.T) {
	h, otherCookie, otherID := profileHarness(t)
	rec := h.do(h.req(http.MethodGet, "/api/account/profile", nil))
	var v profileView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 200 {
		t.Fatalf("%d %v %s", rec.Code, err, rec.Body)
	}
	if !v.PerDevice || len(v.Sessions) != 2 {
		t.Fatalf("view = %+v", v)
	}
	cur := 0
	for _, s := range v.Sessions {
		if s.Current {
			cur++
			if s.Device != "Firefox on Linux" {
				t.Errorf("device = %q", s.Device)
			}
		}
	}
	if cur != 1 {
		t.Errorf("%d current sessions", cur)
	}
	// The other device works until it is signed out here.
	probe := func() int {
		r := httptest.NewRequest(http.MethodGet, "/api/account/security", nil)
		r.AddCookie(otherCookie)
		return h.do(r).Code
	}
	if probe() != 200 {
		t.Fatal("other device should be signed in")
	}
	body, _ := json.Marshal(map[string]string{"id": otherID})
	if rec := h.do(h.authedReq(http.MethodPost, "/api/account/sessions/revoke", body)); rec.Code != 200 {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	if probe() != http.StatusUnauthorized {
		t.Error("revoked device still signed in")
	}
	// This device is untouched, and a second try says so.
	if h.do(h.req(http.MethodGet, "/api/account/security", nil)).Code != 200 {
		t.Error("revoking another device signed this one out")
	}
	if rec := h.do(h.authedReq(http.MethodPost, "/api/account/sessions/revoke", body)); rec.Code != http.StatusNotFound {
		t.Errorf("second revoke = %d", rec.Code)
	}
}

func TestProfile_CannotRevokeSomeoneElsesSession(t *testing.T) {
	h, _, _ := profileHarness(t)
	sm := h.App.Auth.Sessions
	victim, _ := sm.New("friend")
	_ = sm.Registry.Add(auth.SessionRecord{ID: victim.ID, User: "friend", Created: victim.IssuedAt, LastSeen: victim.IssuedAt, Expires: victim.ExpiresAt})
	body, _ := json.Marshal(map[string]string{"id": victim.ID})
	if rec := h.do(h.authedReq(http.MethodPost, "/api/account/sessions/revoke", body)); rec.Code != http.StatusNotFound {
		t.Fatalf("revoking another user's session = %d", rec.Code)
	}
	if !sm.Registry.Touch(victim.ID, time.Now()) {
		t.Error("the other user's session was ended")
	}
}

func TestProfile_RevokeOthersAndAll(t *testing.T) {
	h, otherCookie, _ := profileHarness(t)
	rec := h.do(h.authedReq(http.MethodPost, "/api/account/sessions/revoke", []byte(`{"others":true}`)))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"signed_out":false`) {
		t.Fatalf("others = %d %s", rec.Code, rec.Body)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/account/security", nil)
	r.AddCookie(otherCookie)
	if h.do(r).Code != http.StatusUnauthorized {
		t.Error("other device still signed in")
	}
	rec = h.do(h.authedReq(http.MethodPost, "/api/account/sessions/revoke", []byte(`{"all":true}`)))
	if !strings.Contains(rec.Body.String(), `"signed_out":true`) {
		t.Fatalf("all = %s", rec.Body)
	}
	if h.do(h.req(http.MethodGet, "/api/account/security", nil)).Code != http.StatusUnauthorized {
		t.Error("this device survived sign out everywhere")
	}
}

func TestProfile_RevokeNeedsCSRF(t *testing.T) {
	h, _, _ := profileHarness(t)
	if rec := h.do(h.req(http.MethodPost, "/api/account/sessions/revoke", []byte(`{"all":true}`))); rec.Code != http.StatusForbidden {
		t.Fatalf("without csrf = %d", rec.Code)
	}
}

func TestProfile_DisplayName(t *testing.T) {
	h, _, _ := profileHarness(t)
	save := func(n string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"display_name": n})
		return h.do(h.authedReq(http.MethodPost, "/api/account/profile", b))
	}
	if rec := save("  Captain Scotty "); rec.Code != 200 {
		t.Fatalf("save = %d %s", rec.Code, rec.Body)
	}
	if body := h.get(t, "/account"); !strings.Contains(body, "Captain Scotty") {
		t.Error("account page does not show the display name")
	}
	if body := h.get(t, "/"); !strings.Contains(body, `data-username="tester">Captain Scotty`) {
		t.Error("topbar does not show the display name")
	}
	for _, bad := range []string{strings.Repeat("x", 41), "a\x00b", "a‮b"} {
		if rec := save(bad); rec.Code != http.StatusBadRequest {
			t.Errorf("name %q = %d", bad, rec.Code)
		}
	}
	if rec := save(""); rec.Code != 200 {
		t.Fatal("clearing failed")
	}
	if body := h.get(t, "/"); !strings.Contains(body, `data-username="tester">tester`) {
		t.Error("cleared name should fall back to the sign-in name")
	}
}

func TestDescribeDevice(t *testing.T) {
	for ua, want := range map[string]string{
		"": "Unknown device",
		"Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537": "Chrome on Windows",
		"Mozilla/5.0 (Windows NT 10.0) Chrome/120 Edg/120":    "Edge on Windows",
		"curl/8.5.0": "curl",
	} {
		if got := describeDevice(ua); got != want {
			t.Errorf("describeDevice(%q) = %q, want %q", ua, got, want)
		}
	}
}

func TestHealthReportsOffsite(t *testing.T) {
	h := pagesHarness(t)
	status := filepath.Join(t.TempDir(), "offsite.json")
	h.App.Backups = &backup.Manager{Root: &backup.Root{Mount: t.TempDir()}, OffsiteFile: status}
	get := func() map[string]bool {
		var m map[string]bool
		if err := json.Unmarshal([]byte(h.get(t, "/api/health")), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := get(); m["offsite"] {
		t.Errorf("no status file should read as a problem: %v", m)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	os.WriteFile(status, []byte(`{"ok":true,"at":"`+now+`","last_ok":"`+now+`","interval_seconds":3600,"remote":"r"}`), 0o644)
	if m := get(); !m["offsite"] {
		t.Errorf("a fresh ok report should be healthy: %v", m)
	}
	body := h.get(t, "/api/backups/health")
	if !strings.Contains(body, `"offsite":{"configured":true,"state":"ok"`) {
		t.Errorf("backups health = %s", body)
	}
	h.App.Backups.OffsiteFile = ""
	if _, has := get()["offsite"]; has {
		t.Error("offsite shown while not configured")
	}
}
