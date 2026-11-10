package dockerguard

import (
	"strings"
	"testing"
)

// A container ref is resolved once (one inspect) and the engine is sent the
// full id that inspect gave, so the engine cannot resolve the ref again to a
// container that was never checked (a name / id-prefix collision, a
// container replaced in between).
func TestContainerRefsReachTheEngineAsTheCheckedID(t *testing.T) {
	h := newHarness(t, scopesJSON)
	copyID := strings.Repeat("f6", 32)
	for _, c := range []struct{ method, path, want string }{
		{"GET", "/v1.52/containers/palworld/json", "/v1.52/containers/" + palID + "/json"},
		{"GET", "/v1.52/containers/" + palID[:12] + "/json", "/v1.52/containers/" + palID + "/json"},
		{"GET", "/v1.52/containers/a1a/stats?stream=0", "/v1.52/containers/" + palID + "/stats?stream=0"},
		{"GET", "/v1.52/containers/palworld/top", "/v1.52/containers/" + palID + "/top"},
		{"GET", "/v1.52/containers/palworld/logs?tail=1", "/v1.52/containers/" + palID + "/logs?tail=1"},
		{"POST", "/v1.52/containers/palworld/start", "/v1.52/containers/" + palID + "/start"},
		{"POST", "/v1.52/containers/" + palID + "/stop?t=10", "/v1.52/containers/" + palID + "/stop?t=10"},
		{"POST", "/v1.52/containers/palworld/restart", "/v1.52/containers/" + palID + "/restart"},
		{"POST", "/v1.52/containers/valheim/exec", "/v1.52/containers/" + valID + "/exec"},
		{"DELETE", "/v1.52/containers/c3c3c3?force=1", "/v1.52/containers/" + valID + "?force=1"},
		{"GET", "/v1.52/containers/" + valID[:12] + "_valheim/json", "/v1.52/containers/" + copyID + "/json"},
		{"POST", "/v1.52/containers/" + retiredID[:12] + "_valheim/rename?name=valheim", "/v1.52/containers/" + retiredID + "/rename?name=valheim"},
	} {
		h.eng.clear()
		var body any
		if strings.HasSuffix(c.path, "/exec") {
			body = map[string]any{"Cmd": []any{"status"}}
		}
		if r := h.request(c.method, c.path, body); r.code >= 300 {
			t.Fatalf("%s %s: %s", c.method, c.path, r)
		}
		seen := h.eng.all()
		last := seen[len(seen)-1]
		if last.method != c.method || last.uri != c.want {
			t.Errorf("%s %s reached the engine as %s %s, want %s", c.method, c.path, last.method, last.uri, c.want)
		}
		want := 1 // the one inspect the decision was made on, then the request itself
		if strings.Contains(c.path, "_valheim/json") {
			want = 2 // and the current container the copy's name says it replaces
		}
		if len(seen) != want+1 {
			t.Errorf("%s %s: engine saw %d requests, want %d inspects and the request", c.method, c.path, len(seen), want)
		}
	}
}

func TestOnlyAPlainFullIDIsForwarded(t *testing.T) {
	for _, id := range []string{"", palID[:12], strings.ToUpper(palID), palID + "/x", "../" + palID[3:]} {
		if containerIDRe.MatchString(id) {
			t.Errorf("%q accepted as a full id", id)
		}
	}
	if c := (&resolved{id: palID}); c.path("/start") != "/containers/"+palID+"/start" {
		t.Fatal(c.path("/start"))
	}
}
