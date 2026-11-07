package execguard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type upstream struct {
	mu   sync.Mutex
	hits []string
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.hits = append(u.hits, r.Method+" "+r.URL.Path)
	u.mu.Unlock()
	if strings.HasSuffix(r.URL.Path, "/exec") {
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"Id":"abc123"}`)
		return
	}
	io.WriteString(w, "ok")
}

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.hits)
}

func setup(t *testing.T) (*Guard, *upstream, *httptest.Server) {
	t.Helper()
	up := &upstream{}
	us := httptest.NewServer(up)
	t.Cleanup(us.Close)
	g, err := New("tcp://"+strings.TrimPrefix(us.URL, "http://"), []Rule{
		{Container: "pal", Cmd: []string{"/bin/sh", "-c", "backup"}},
		{Container: "pal", Cmd: []string{"find", "/b", "-type", "f"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	gs := httptest.NewServer(g)
	t.Cleanup(gs.Close)
	return g, up, gs
}

func do(t *testing.T, method, url, body string) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestCreate(t *testing.T) {
	_, up, gs := setup(t)
	cases := []struct {
		name, path, body string
		want             int
	}{
		{"allowed", "/v1.43/containers/pal/exec", `{"AttachStdout":true,"Cmd":["/bin/sh","-c","backup"],"Env":null,"User":""}`, 201},
		{"unversioned", "/containers/pal/exec", `{"Cmd":["find","/b","-type","f"]}`, 201},
		{"other command", "/containers/pal/exec", `{"Cmd":["/bin/sh","-c","backup; id"]}`, 403},
		{"prefix of allowed", "/containers/pal/exec", `{"Cmd":["/bin/sh","-c"]}`, 403},
		{"other container", "/containers/other/exec", `{"Cmd":["/bin/sh","-c","backup"]}`, 403},
		{"privileged", "/containers/pal/exec", `{"Cmd":["/bin/sh","-c","backup"],"Privileged":true}`, 403},
		{"user", "/containers/pal/exec", `{"Cmd":["/bin/sh","-c","backup"],"User":"root"}`, 403},
		{"env", "/containers/pal/exec", `{"Cmd":["/bin/sh","-c","backup"],"Env":["A=1"]}`, 403},
		{"workdir", "/containers/pal/exec", `{"Cmd":["/bin/sh","-c","backup"],"WorkingDir":"/"}`, 403},
		{"unknown option", "/containers/pal/exec", `{"Cmd":["/bin/sh","-c","backup"],"Mounts":[]}`, 403},
		{"no cmd", "/containers/pal/exec", `{}`, 403},
		{"garbage", "/containers/pal/exec", `nope`, 403},
		{"encoded path", "/containers/p%61l/exec", `{"Cmd":["/bin/sh","-c","backup"]}`, 403},
		{"dot segments", "/containers/other/../pal/exec", `{"Cmd":["/bin/sh","-c","backup"]}`, 403},
		{"double slash", "//containers/pal/exec", `{"Cmd":["/bin/sh","-c","backup"]}`, 403},
	}
	for _, c := range cases {
		before := up.count()
		if got := do(t, "POST", gs.URL+c.path, c.body); got != c.want {
			t.Errorf("%s: status %d, want %d", c.name, got, c.want)
		}
		if c.want == 403 && up.count() != before {
			t.Errorf("%s: denied request reached upstream", c.name)
		}
	}
}

func TestStartOnlyForIssuedIDs(t *testing.T) {
	g, up, gs := setup(t)
	if got := do(t, "POST", gs.URL+"/exec/abc123/start", `{}`); got != 403 {
		t.Fatalf("start before create: %d", got)
	}
	do(t, "POST", gs.URL+"/containers/pal/exec", `{"Cmd":["/bin/sh","-c","backup"]}`)
	if got := do(t, "POST", gs.URL+"/exec/abc123/start", `{}`); got != 200 {
		t.Fatalf("start of issued id: %d", got)
	}
	if got := do(t, "POST", gs.URL+"/exec/zzz/start", `{}`); got != 403 {
		t.Fatalf("start of foreign id: %d", got)
	}
	if got := do(t, "GET", gs.URL+"/exec/zzz/json", ""); got != 200 {
		t.Fatalf("inspect: %d", got)
	}
	// ids expire
	g.now = func() time.Time { return time.Now().Add(idTTL + time.Second) }
	if got := do(t, "POST", gs.URL+"/exec/abc123/start", `{}`); got != 403 {
		t.Fatalf("start of expired id: %d", got)
	}
	_ = up
}

func TestOtherRoutesPassThrough(t *testing.T) {
	_, up, gs := setup(t)
	if got := do(t, "GET", gs.URL+"/v1.43/containers/json", ""); got != 200 {
		t.Fatalf("passthrough: %d", got)
	}
	if got := do(t, "POST", gs.URL+"/v1.43/containers/pal/stop", ""); got != 200 {
		t.Fatalf("passthrough stop: %d", got)
	}
	if up.count() != 2 {
		t.Fatalf("upstream hits = %d", up.count())
	}
	if got := do(t, "POST", gs.URL+"/exec/abc/other", ""); got != 403 {
		t.Fatalf("unknown exec route: %d", got)
	}
	if got := do(t, "GET", gs.URL+"/containers/pal/exec", ""); got != 403 {
		t.Fatalf("GET on create route: %d", got)
	}
}
