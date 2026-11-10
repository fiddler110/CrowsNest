package dockerguard

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPolicy = `
games_root: /srv/games
names: [valheim, palworld, "gs-*"]
images: [lloesche/valheim-server, "ghcr.io/example/*"]
networks: [crowsnest-games-net]
ports: ["27000-27999/udp", "25565/tcp"]
host_ips: [10.0.0.2]
`

func scopeJSON(name, image string, extra string) string {
	return `{"name":"` + name + `","images":["` + image + `"],"binds":["/srv/games/` + name + `"],"networks":["crowsnest-games-net"],` +
		`"ports":[{"host_ip":"10.0.0.2","host_port":"27015","container_port":"27015","proto":"udp"}]` + extra + `}`
}

func mustScope(t *testing.T, js string) *Scope {
	t.Helper()
	l, err := LoadScopes("[" + js + "]")
	if err != nil {
		t.Fatal(err)
	}
	return l[0]
}

func TestPolicyAdmit(t *testing.T) {
	p, err := ParsePolicy([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	ok := scopeJSON("valheim", "lloesche/valheim-server", `,"exec":false`)
	if err := p.Admit(mustScope(t, ok)); err != nil {
		t.Fatalf("a scope inside the envelope was refused: %v", err)
	}
	cases := map[string]struct{ js, want string }{
		"name":      {scopeJSON("caddy", "lloesche/valheim-server", ""), "names"},
		"prefix ok": {strings.Replace(scopeJSON("gs-one", "lloesche/valheim-server", ""), "gs-one", "gs-one", 1), ""},
		"image":     {scopeJSON("valheim", "evil/miner", ""), "images"},
		"bind":      {strings.Replace(scopeJSON("valheim", "lloesche/valheim-server", ""), "/srv/games/valheim", "/etc", 1), "games_root"},
		"bind root": {strings.Replace(scopeJSON("valheim", "lloesche/valheim-server", ""), "/srv/games/valheim", "/srv/games", 1), "games_root"},
		"network":   {strings.Replace(scopeJSON("valheim", "lloesche/valheim-server", ""), "crowsnest-games-net", "bridge", 1), "networks"},
		"port":      {strings.Replace(scopeJSON("valheim", "lloesche/valheim-server", ""), `"27015","container_port":"27015"`, `"22","container_port":"27015"`, 1), "port"},
		"proto":     {strings.Replace(scopeJSON("valheim", "lloesche/valheim-server", ""), `"udp"`, `"tcp"`, 1), "port"},
		"hostip":    {strings.Replace(scopeJSON("valheim", "lloesche/valheim-server", ""), "10.0.0.2", "0.0.0.0", 1), "host_ip"},
		"exec":      {scopeJSON("valheim", "lloesche/valheim-server", `,"exec":true`), "exec"},
		"secopts":   {scopeJSON("valheim", "lloesche/valheim-server", `,"secopts":["seccomp=unconfined"]`), "no exception"},
		"cap_add":   {scopeJSON("valheim", "lloesche/valheim-server", `,"cap_add":["NET_ADMIN"]`), "cannot carry"},
		"ipv4":      {scopeJSON("valheim", "lloesche/valheim-server", `,"ipv4":{"crowsnest-games-net":["10.0.1.5"]}`), "no exception"},
		"label":     {scopeJSON("valheim", "lloesche/valheim-server", `,"labels":{"caddy":"x"}`), "label"},
	}
	for name, c := range cases {
		err := p.Admit(mustScope(t, c.js))
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: want admitted, got %v", name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: want an error about %q, got %v", name, c.want, err)
		}
	}
}

const exceptionPolicy = testPolicy + `
exceptions:
  - name: windrose
    image: indifferentbroccoli/windrose-server-docker
    networks:
      dockervlan: [10.0.1.16]
      crowsnest-games-net: [192.168.0.50]
    secopts: [seccomp=unconfined]
`

func windroseScope(extra string) string {
	return `{"name":"windrose","images":["indifferentbroccoli/windrose-server-docker"],"binds":["/srv/games/Windrose/Config"],` +
		`"networks":["dockervlan","crowsnest-games-net"],"ipv4":{"dockervlan":["10.0.1.16"],"crowsnest-games-net":["192.168.0.50"]},` +
		`"secopts":["seccomp=unconfined","seccomp:unconfined"]` + extra + `}`
}

// A policy exception admits exactly one container with exactly what it lists.
func TestPolicyException(t *testing.T) {
	p, err := ParsePolicy([]byte(exceptionPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Admit(mustScope(t, windroseScope(""))); err != nil {
		t.Fatalf("the excepted game was refused: %v", err)
	}
	for name, c := range map[string]struct{ js, want string }{
		"other address": {strings.Replace(windroseScope(""), "10.0.1.16", "10.0.1.99", 2), "10.0.1.99"},
		"other network": {strings.ReplaceAll(windroseScope(""), "dockervlan", "othervlan"), "othervlan"},
		"other image":   {strings.Replace(windroseScope(""), "indifferentbroccoli/windrose-server-docker", "evil/miner", 1), "images"},
		"other name":    {strings.Replace(windroseScope(""), `"name":"windrose"`, `"name":"windrose2"`, 1), "names"},
		"cap_add":       {windroseScope(`,"cap_add":["NET_ADMIN"]`), "cannot carry"},
		"other secopt":  {strings.Replace(windroseScope(""), `"seccomp=unconfined","seccomp:unconfined"`, `"apparmor=unconfined"`, 1), "apparmor"},
	} {
		err := p.Admit(mustScope(t, c.js))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error about %q, got %v", name, c.want, err)
		}
	}
	// the exception names one game: another game gets none of it
	other := strings.Replace(windroseScope(""), `"name":"windrose"`, `"name":"gs-win"`, 1)
	if err := p.Admit(mustScope(t, other)); err == nil {
		t.Error("a second game inherited the exception")
	}
}

func TestPolicyExceptionParse(t *testing.T) {
	for name, y := range map[string]string{
		"wildcard name": strings.Replace(exceptionPolicy, "name: windrose", `name: "win*"`, 1),
		"tagged image":  strings.Replace(exceptionPolicy, "server-docker", "server-docker:latest", 1),
		"bad address":   strings.Replace(exceptionPolicy, "10.0.1.16", "0.0.0.0", 1),
		"host network":  strings.Replace(exceptionPolicy, "dockervlan:", "host:", 1),
		"unknown key":   exceptionPolicy + "    privileged: true\n",
	} {
		if _, err := ParsePolicy([]byte(y)); err == nil {
			t.Errorf("%s: policy was accepted", name)
		}
	}
}

func TestPolicyParseRefusesLooseness(t *testing.T) {
	for name, y := range map[string]string{
		"no names":   strings.Replace(testPolicy, "names: [valheim, palworld, \"gs-*\"]", "", 1),
		"star name":  strings.Replace(testPolicy, "valheim,", "\"*\",", 1),
		"no ports":   strings.Replace(testPolicy, "ports: [\"27000-27999/udp\", \"25565/tcp\"]", "", 1),
		"no proto":   strings.Replace(testPolicy, "25565/tcp", "25565", 1),
		"host net":   strings.Replace(testPolicy, "crowsnest-games-net", "host", 1),
		"relative":   strings.Replace(testPolicy, "/srv/games", "games", 1),
		"root":       strings.Replace(testPolicy, "/srv/games", "/", 1),
		"unknown":    testPolicy + "\nprivileged: true\n",
		"tagged img": strings.Replace(testPolicy, "lloesche/valheim-server", "lloesche/valheim-server:latest", 1),
	} {
		if _, err := ParsePolicy([]byte(y)); err == nil {
			t.Errorf("%s: policy was accepted", name)
		}
	}
}

func TestSourcesLoadAndWatch(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	managed := filepath.Join(dir, "scopes.json")
	write := func(path, s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(pol, testPolicy)
	base := `[{"name":"panel-own","images":["crowsnest/x"],"exec":true}]`
	src := Sources{Base: base, ManagedFile: managed, PolicyFile: pol}

	// no managed file yet: just the operator's scopes
	res, err := src.Load()
	if err != nil || len(res.Scopes) != 1 || res.Managed != 0 {
		t.Fatalf("fresh install: %+v %v", res, err)
	}
	// one good, one outside the envelope, one shadowing an operator scope
	write(managed, "["+scopeJSON("valheim", "lloesche/valheim-server", "")+","+scopeJSON("caddy", "lloesche/valheim-server", "")+","+
		scopeJSON("panel-own", "lloesche/valheim-server", "")+"]")
	res, err = src.Load()
	if err != nil || len(res.Scopes) != 2 || res.Managed != 1 || len(res.Rejected) != 2 {
		t.Fatalf("mixed file: scopes=%d managed=%d rejected=%v err=%v", len(res.Scopes), res.Managed, res.Rejected, err)
	}

	// managed scopes with no policy are never loaded
	if _, err := (Sources{Base: base, ManagedFile: managed}).Load(); err == nil {
		t.Error("managed file without a policy was accepted")
	}
	// a broken policy or managed file fails the load
	write(pol, "games_root: nope")
	if _, err := src.Load(); err == nil {
		t.Error("broken policy was accepted")
	}
	write(pol, testPolicy)
	write(managed, "{not json")
	if _, err := src.Load(); err == nil {
		t.Error("broken managed file was accepted")
	}

	// Watch: picks up a change, keeps the old scopes on a bad one, honours a tighter policy.
	write(managed, "[]")
	res, _ = src.Load()
	g := New("/nonexistent.sock", res.Scopes)
	g.Logf = t.Logf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	go func() { g.Watch(ctx, src, 10*time.Millisecond, nil, res); close(done) }()
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for i := 0; i < 300; i++ {
			if cond() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
	}
	has := func(n string) func() bool { return func() bool { return g.cur().byName[n] != nil } }
	write(managed, "["+scopeJSON("valheim", "lloesche/valheim-server", "")+"]")
	waitFor("valheim to load", has("valheim"))
	write(managed, "{broken")
	time.Sleep(100 * time.Millisecond)
	if !has("valheim")() {
		t.Fatal("a broken file dropped the scopes in force")
	}
	write(managed, "["+scopeJSON("valheim", "lloesche/valheim-server", "")+"]")
	write(pol, strings.Replace(testPolicy, "valheim, ", "", 1))
	waitFor("valheim to be dropped by the tighter policy", func() bool { return !has("valheim")() })
	if !has("panel-own")() {
		t.Fatal("the operator's own scope was dropped")
	}
}
