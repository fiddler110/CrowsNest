package probes

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"
)

func TestHTTPJSON_PlayersShapes(t *testing.T) {
	cases := []struct {
		body, count, names, field string
		want                      int
		wantNames                 []string
		ok                        bool
	}{
		{`{"players":[{"name":"a"},{"name":"b"}]}`, "players", "", "name", 2, []string{"a", "b"}, true},
		{`{"server":{"player_count":3},"players":["x","y","z"]}`, "server.player_count", "players", "", 3, []string{"x", "y", "z"}, true},
		{`{"players":[]}`, "players", "", "name", 0, []string{}, true},
		{`{"other":1}`, "players", "", "", 0, nil, false},
		{`{"players":"many"}`, "players", "", "", 0, nil, false},
		{`{"n":-1}`, "n", "", "", 0, nil, false},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, p, _ := r.BasicAuth()
			if u != "admin" || p != "pw" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(c.body))
		}))
		p := &HTTPJSON{URL: srv.URL, User: "admin", Pass: "pw", CountPath: c.count, NamesPath: c.names, NameField: c.field}
		n, names, ok := p.PlayerCount(context.Background())
		srv.Close()
		if ok != c.ok || n != c.want || len(names) != len(c.wantNames) {
			t.Errorf("%s: got %d %v %v", c.body, n, names, ok)
		}
	}
}

func TestHTTPJSON_AuthFailureIsUndeterminable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer srv.Close()
	if _, _, ok := (&HTTPJSON{URL: srv.URL, CountPath: "n"}).PlayerCount(context.Background()); ok {
		t.Fatal("401 must be ok=false")
	}
}

func TestSourceRCON(t *testing.T) {
	reply := "hostname: x\n# userid name uniqueid\n# 2 \"Alice\" STEAM_1\n# 3 \"Bob\" STEAM_2\n"
	p := &SourceRCON{Command: "status", Pattern: regexp.MustCompile(`^# \d+ "([^"]+)"`),
		Exec: func(context.Context, string, string, string, time.Duration) (string, error) { return reply, nil }}
	n, names, ok := p.PlayerCount(context.Background())
	if !ok || n != 2 || names[0] != "Alice" || names[1] != "Bob" {
		t.Fatalf("got %d %v %v", n, names, ok)
	}
	p.Exec = func(context.Context, string, string, string, time.Duration) (string, error) {
		return "", errors.New("refused")
	}
	if _, _, ok := p.PlayerCount(context.Background()); ok {
		t.Fatal("rcon error must be ok=false")
	}
}
