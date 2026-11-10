package dockerguard

// Fuzz targets for the two parsers between a client and the checks: the
// request target and the JSON bodies. Neither may panic, and whatever they
// accept must survive being re-encoded (what the engine is sent) and read
// again unchanged.
//
//	go test -run='^$' -fuzz=FuzzRequestTarget -fuzztime=20s ./internal/dockerguard
//	go test -run='^$' -fuzz=FuzzCheckBody -fuzztime=20s ./internal/dockerguard

import (
	"reflect"
	"strings"
	"testing"
)

func FuzzRequestTarget(f *testing.F) {
	for _, s := range []string{
		"/_ping", "/v1.52/version", "/v1.52/containers/palworld/json", "/v1.52/containers/" + palID[:12] + "/json",
		"/v1.52/containers/palworld/logs?stdout=1&stderr=1&tail=100", "/v1.52/containers/palworld/stats?stream=0",
		"/v1.52/containers/palworld/top?ps_args=%2Def", "/v01.052/containers/palworld/top?ps_args=a+b",
		"/v1.52/containers/json?all=1&filters=%7B%22label%22%3A%5B%22x%22%5D%7D", "/v1.52/containers/create?name=palworld",
		"/v1.52/containers/" + valID[:12] + "_valheim/rename?name=valheim", "/v1.52/containers/valheim?v=false&force=false&link=false",
		"/v1.52/images/create?fromImage=thijsvanloef%2Fpalworld-server-docker&tag=latest", "/v1.52/containers/palworld/json;x",
		"/v1.40/containers/palworld/json", "/v1.52/containers/palworld%2Fjson", "/containers/palworld/json?x=%zz",
		"/v1.52/containers/palworld/logs?#&follow=1", "/v1.52", "/v1.52?x", "/v", "/?=&=", "/v1.52/networks/crowsnest-games-net",
	} {
		f.Add(s, uint8(0))
	}
	h := newHarness(f, scopesJSON)
	methods := []string{"GET", "POST", "DELETE", "HEAD"}
	f.Fuzz(func(t *testing.T, target string, m uint8) {
		req := &request{}
		if req.parseTarget(target) != nil {
			return
		}
		again := &request{}
		if rf := again.parseTarget(req.target()); rf != nil {
			t.Fatalf("%q accepted, its rebuilt target %q refused: %s", target, req.target(), rf.msg)
		}
		if again.version != req.version || again.path != req.path || !reflect.DeepEqual(again.query.pairs, req.query.pairs) {
			t.Fatalf("%q rebuilt as %q reads differently: %+v vs %+v", target, req.target(), again, req)
		}
		if again.target() != req.target() {
			t.Fatalf("rebuilding is not stable: %q then %q", req.target(), again.target())
		}
		// the checks themselves, against the fake engine: no panic, and a rewritten target still parses
		method := methods[int(m)%len(methods)]
		_, fwd, err := h.g.check(method, req.path, req.query, nil)
		if err != nil {
			return
		}
		out := &request{version: req.version, path: fwd, query: req.query}
		if rf := (&request{}).parseTarget(out.target()); rf != nil {
			t.Fatalf("%s %q passed, forwarded as %q which does not parse: %s", method, target, out.target(), rf.msg)
		}
		if fwd != req.path && !strings.HasPrefix(fwd, "/containers/") {
			t.Fatalf("%s %q: unexpected rewrite to %q", method, target, fwd)
		}
	})
}

func FuzzCheckBody(f *testing.F) {
	fill := strings.NewReplacer("PALDIR", palDir, "OTHERNETID", otherNetID, "NETID", netID, "PALIMG", palImageID, "DIGEST", digest)
	for _, s := range []string{
		composeJSON,
		`{"Image": "lloesche/valheim-server", "HostConfig": {"NetworkMode": "crowsnest-games-net"}}`,
		`{"Image": "thijsvanloef/palworld-server-docker@DIGEST", "HostConfig": {"NetworkMode": "NETID"},
		  "NetworkingConfig": {"EndpointsConfig": {"NETID": {"Aliases": ["palworld"]}}}}`,
		`{"Image": "lloesche/valheim-server", "HostConfig": {"NetworkMode": "crowsnest-games-net",
		  "Mounts": [{"Type": "volume", "Source": "crowsnest-games_saves", "Target": "/config"}], "Binds": ["/srv/valheim:/config/x:rw"]}}`,
		`{"Image": "alpine", "HostConfig": {"Privileged": true, "Binds": ["/:/host"]}}`,
		`{"Cmd": ["status"], "AttachStdout": true, "AttachStdin": true, "User": "", "Privileged": false}`,
		`{"Detach": false, "Tty": false, "ConsoleSize": [24, 80]}`,
		`{"Image": "thijsvanloef/palworld-server-docker:latest@DIGEST", "HostConfig": {"NetworkMode": "crowsnest-games-net"}}`,
		`{"Image": "docker.io/thijsvanloef/palworld-server-docker@DIGEST", "HostConfig": {"NetworkMode": "crowsnest-games-net"}}`,
		`{"Source": "/ok", "source": "/"}`, `{"a": {"b": {"c": [1, 2.5, -0, 1e3]}}}`, `null`, `[]`, `"x"`,
	} {
		for kind := uint8(0); kind < 6; kind++ {
			f.Add([]byte(fill.Replace(s)), kind)
		}
	}
	h := newHarness(f, scopesJSON)
	pinned := newHarness(f, scopesJSON, pinPalworld) // palworld as a managed scope under pin_digests
	check := func(kind uint8, body any) error {
		switch kind % 6 {
		case 0:
			return h.g.checkCreate(query{pairs: [][2]string{{"name", "palworld"}}, vals: map[string][]string{"name": {"palworld"}}}, body)
		case 1:
			return h.g.checkCreate(query{pairs: [][2]string{{"name", "valheim"}}, vals: map[string][]string{"name": {"valheim"}}}, body)
		case 2:
			tmp := valID[:12] + "_valheim"
			return h.g.checkCreate(query{pairs: [][2]string{{"name", tmp}}, vals: map[string][]string{"name": {tmp}}}, body)
		case 5:
			return pinned.g.checkCreate(query{pairs: [][2]string{{"name", "palworld"}}, vals: map[string][]string{"name": {"palworld"}}}, body)
		case 3:
			_, err := h.g.checkPost("/containers/valheim/exec", query{vals: map[string][]string{}}, body, new(string))
			return err
		default:
			_, err := checkObject(body, execStartRules, "ExecStart")
			return err
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte, kind uint8) {
		body, err := strictJSON(raw)
		if err != nil {
			return
		}
		if check(kind, body) != nil {
			return
		}
		enc, err := marshal(body)
		if err != nil {
			t.Fatalf("accepted body does not re-encode: %v", err)
		}
		again, err := strictJSON(enc)
		if err != nil {
			t.Fatalf("accepted body re-encodes to %q, which does not parse: %v", enc, err)
		}
		if !reflect.DeepEqual(again, body) {
			t.Fatalf("accepted body reads differently once re-encoded: %q", enc)
		}
		if err := check(kind, again); err != nil {
			t.Fatalf("accepted body refused once re-encoded (%q): %v", enc, err)
		}
	})
}
