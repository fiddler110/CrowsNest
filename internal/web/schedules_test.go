package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/schedule"
)

func TestSchedulesAPI(t *testing.T) {
	h := newHarness(t, "#!/bin/sh\nexit 0\n")
	st, _ := schedule.Open(filepath.Join(t.TempDir(), "s.json"))
	h.App.Schedules = st
	call := func(method, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.mux().ServeHTTP(rec, h.authedReq(method, "/api/schedules", []byte(body)))
		return rec
	}
	if rec := call("GET", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"schedules":[]`) {
		t.Fatalf("empty get = %d %s", rec.Code, rec.Body.String())
	}
	good := `{"schedules":[{"id":"fri","game":"windrose","action":"start","days":[5],"time":"18:00","enabled":true}]}`
	if rec := call("PUT", good); rec.Code != 200 || len(st.List()) != 1 {
		t.Fatalf("put = %d %s", rec.Code, rec.Body.String())
	}
	for name, body := range map[string]string{
		"unknown game": strings.Replace(good, "windrose", "nope", 1),
		"bad time":     strings.Replace(good, "18:00", "25:00", 1),
		"unknown key":  `{"schedules":[],"x":1}`,
	} {
		if rec := call("PUT", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d", name, rec.Code)
		}
	}
	if len(st.List()) != 1 {
		t.Error("a refused save changed the list")
	}
}
