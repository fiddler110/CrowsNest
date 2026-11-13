package probes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/games"
)

func TestFormatAndDuration(t *testing.T) {
	cases := []struct {
		v    any
		f    string
		want string
	}{
		{5, "", "5"},
		{90061, "duration", "1d 1h"},
		{3700, "duration", "1h 1m"},
		{125, "duration", "2m"},
		{7, "duration", "7s"},
		{3.14159, "%.1f", "3.1"},
		{3.9, "%d", "3"},
		{"x", "%.1f", "x"},
		{"2.5", "%.1f", "2.5"},
		{true, "weird", "true"},
	}
	for _, c := range cases {
		if got := format(c.v, c.f); got != c.want {
			t.Errorf("format(%v,%q) = %q, want %q", c.v, c.f, got, c.want)
		}
	}
	if _, ok := toFloat(struct{}{}); ok {
		t.Error("toFloat of a struct must fail")
	}
}

func TestRenderValue(t *testing.T) {
	get := func(n string) (any, bool) {
		switch n {
		case "n":
			return float64(4), true
		case "s":
			return "hi", true
		case "empty":
			return "", true
		}
		return nil, false
	}
	if v, ok := renderValue("{n}", get); !ok || v != 4 {
		t.Errorf("bare number: %v %v", v, ok)
	}
	if _, ok := renderValue("{empty}", get); ok {
		t.Error("bare empty string must be dropped")
	}
	if v, ok := renderValue("{s} has {n|%d}", get); !ok || v != "hi has 4" {
		t.Errorf("mixed: %v %v", v, ok)
	}
	if _, ok := renderValue("{s} {missing}", get); ok {
		t.Error("unresolved placeholder must drop the field")
	}
	if got := renderString("a {x} b {y}", map[string]string{"x": "1"}); got != "a 1 b " {
		t.Errorf("renderString = %q", got)
	}
}

func restServer(t *testing.T) (*HTTPJSON, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path+" "+string(b))
		mu.Unlock()
		switch r.URL.Path {
		case "/info":
			w.Write([]byte(`{"version":"1.2","name":"Srv","uptime":90000}`))
		case "/players":
			w.Write([]byte(`{"players":[{"name":"a"},{"name":"b"}]}`))
		case "/bans":
			w.Write([]byte(`{"bans":[{"id":"1","why":"x"},{"id":"2","why":"y"}]}`))
		case "/empty":
			w.Write([]byte(`{"bans":[]}`))
		case "/fail":
			w.WriteHeader(500)
		default:
			w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return &HTTPJSON{BaseURL: srv.URL, Name: "t", StatusPath: "/info", PlayersPath: "/players", CountPath: "players", NameField: "name"}, &calls
}

func TestHTTPJSON_Info(t *testing.T) {
	p, _ := restServer(t)
	p.InfoSources = []InfoSource{{Name: "i", Path: "/info", Required: true}, {Name: "gone", Path: "/fail"}}
	p.InfoFields = []InfoField{
		{Key: "version", Template: "{i.version}"},
		{Key: "up", Template: "{i.uptime|duration}"},
		{Key: "dropped", Template: "{gone.x}"},
	}
	out, ok := p.Info(context.Background())
	if !ok || out["version"] != "1.2" || out["up"] != "1d 1h" {
		t.Fatalf("got %v %v", out, ok)
	}
	if _, has := out["dropped"]; has {
		t.Error("field from a failed optional source must be left out")
	}
	p.InfoSources = []InfoSource{{Name: "i", Path: "/fail", Required: true}}
	if _, ok := p.Info(context.Background()); ok {
		t.Error("a failed required source must make the panel unavailable")
	}
}

func TestHTTPJSON_ActionsAndRun(t *testing.T) {
	p, calls := restServer(t)
	p.ActionDefs = []Action{
		{ID: "kick", Label: "Kick", Danger: true,
			Fields:  []Field{{Name: "who", Label: "Player", Max: 5}, {Name: "why", Optional: true}},
			Request: Request{Method: "POST", Path: "/kick", Body: map[string]string{"user": "{who}", "why": "{why}"}},
			Result:  "Kicked {who}"},
		{ID: "bans", Request: Request{Path: "/bans"}, List: &List{Path: "bans", Line: "{id}: {why}"}},
		{ID: "nobans", Request: Request{Path: "/empty"}, List: &List{Path: "bans", Empty: "none"}},
		{ID: "save", Request: Request{Path: "/save"}},
		{ID: "broken", Request: Request{Path: "/fail"}},
	}
	acts := p.Actions()
	if len(acts) != 5 || !acts[0].Danger || len(acts[0].Fields) != 2 || !acts[0].Fields[1].Optional {
		t.Fatalf("Actions = %+v", acts)
	}
	ctx := context.Background()
	if out, err := p.Run(ctx, "kick", map[string]string{"who": " bob "}); err != nil || out != "Kicked bob" {
		t.Fatalf("kick: %q %v", out, err)
	}
	var body map[string]string
	last := (*calls)[len(*calls)-1]
	if err := json.Unmarshal([]byte(strings.SplitN(last, " ", 3)[2]), &body); err != nil || body["user"] != "bob" || body["why"] != "" {
		t.Errorf("request sent %q", last)
	}
	if out, _ := p.Run(ctx, "bans", nil); out != "1: x\n2: y" {
		t.Errorf("list = %q", out)
	}
	if out, _ := p.Run(ctx, "nobans", nil); out != "none" {
		t.Errorf("empty list = %q", out)
	}
	if out, _ := p.Run(ctx, "save", nil); out != "Done." {
		t.Errorf("default result = %q", out)
	}
	if _, err := p.Run(ctx, "broken", nil); err == nil {
		t.Error("a failing request must error")
	}
	if _, err := p.Run(ctx, "nope", nil); err == nil {
		t.Error("unknown action must error")
	}
	for name, args := range map[string]map[string]string{
		"missing":  {},
		"too long": {"who": "abcdefg"},
		"control":  {"who": "a\x07b"},
	} {
		if _, err := p.Run(ctx, "kick", args); !errors.Is(err, games.ErrBadInput) {
			t.Errorf("%s: err = %v, want ErrBadInput", name, err)
		}
	}
}

func TestHTTPJSON_PrepareStop(t *testing.T) {
	p, calls := restServer(t)
	var slept []time.Duration
	p.Sleep = func(_ context.Context, d time.Duration) { slept = append(slept, d) }
	p.Steps = []Step{
		{IfPlayers: true, Request: Request{Method: "POST", Path: "/announce"}, Pause: time.Second},
		{BestEffort: true, Request: Request{Path: "/fail"}},
		{Request: Request{Path: "/save"}},
	}
	if err := p.PrepareStop(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(*calls) < 4 || len(slept) != 1 || slept[0] != time.Second {
		t.Errorf("calls=%v slept=%v", *calls, slept)
	}
	p.Steps = []Step{{Request: Request{Path: "/fail"}}}
	if err := p.PrepareStop(context.Background()); err == nil {
		t.Error("a failing required step must be reported")
	}
}

func TestHTTPJSON_PrepareStopSkipsWhenEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/players" {
			w.Write([]byte(`{"players":[]}`))
			return
		}
		t.Errorf("unexpected request %s", r.URL.Path)
	}))
	defer srv.Close()
	p := &HTTPJSON{BaseURL: srv.URL, PlayersPath: "/players", CountPath: "players",
		Steps: []Step{{IfPlayers: true, Request: Request{Path: "/announce"}}}}
	if err := p.PrepareStop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPJSON_StatusPathFallbacks(t *testing.T) {
	if (&HTTPJSON{PlayersPath: "/p"}).statusPath() != "/p" || (&HTTPJSON{StatusPath: "/s"}).playersPath() != "/s" {
		t.Error("status and players paths must fall back to each other")
	}
}

func TestRawRCON(t *testing.T) {
	var got string
	r := &RawRCON{Addr: "h:1", Password: "p", Exec: func(_ context.Context, _, _, c string, _ time.Duration) (string, error) {
		got = c
		return "ok", nil
	}}
	if out, err := r.Raw(context.Background(), "  list  "); err != nil || out != "ok" || got != "list" {
		t.Fatalf("%q %v %q", out, err, got)
	}
	for _, bad := range []string{"", "a\nb", strings.Repeat("x", 1001)} {
		if _, err := r.Raw(context.Background(), bad); !errors.Is(err, games.ErrBadInput) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	if _, err := (&RawRCON{}).Raw(context.Background(), "x"); err == nil {
		t.Error("unconfigured rcon must error")
	}
}

func TestRCONActions(t *testing.T) {
	var got string
	r := &RCONActions{Addr: "x:1", Password: "pw",
		Defs: []Action{
			{ID: "whitelist_add", Label: "Whitelist add", Fields: []Field{{Name: "player", Max: 16}}, RCON: "whitelist add {player}", Result: "Added {player}."},
			{ID: "list", Label: "List", RCON: "whitelist list"},
		},
		Exec: func(_ context.Context, _, _, cmd string, _ time.Duration) (string, error) {
			got = cmd
			return "reply", nil
		}}
	if out, err := r.Run(context.Background(), "whitelist_add", map[string]string{"player": " Steve "}); err != nil || out != "Added Steve." || got != "whitelist add Steve" {
		t.Fatalf("add = %q %v (sent %q)", out, err, got)
	}
	if out, _ := r.Run(context.Background(), "list", nil); out != "reply" {
		t.Errorf("list = %q", out)
	}
	got = ""
	for name, args := range map[string]map[string]string{"empty": {}, "newline": {"player": "a\nop b"}, "long": {"player": strings.Repeat("a", 17)}} {
		if _, err := r.Run(context.Background(), "whitelist_add", args); !errors.Is(err, games.ErrBadInput) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := r.Run(context.Background(), "nope", nil); err == nil {
		t.Error("an undeclared action ran")
	}
	if got != "" {
		t.Errorf("a refused action still sent %q", got)
	}
}
