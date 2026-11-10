package dockerguard

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const create = "/v1.52/containers/create?name=palworld"

func pathOf(p string) string { s, _, _ := strings.Cut(p, "?"); return s }

// ---------------------------------------------------------------- what compose and the CLI need, allowed

func TestComposeCreateForPalworldIsAllowed(t *testing.T) {
	h := newHarness(t, scopesJSON)
	if r := h.request("POST", create, composeBody(t)); r.code != 201 {
		t.Fatal(r)
	}
	if n := len(h.reached("POST", "/containers/create")); n != 1 {
		t.Fatalf("engine saw %d creates", n)
	}
}

func TestComposeCreateWithMountsInsteadOfBindsIsAllowed(t *testing.T) {
	h := newHarness(t, scopesJSON)
	body := composeBody(t, `{"Binds": null, "Mounts": [
	  {"Type": "bind", "Source": "PALDIR", "Target": "/palworld", "BindOptions": {"CreateMountpoint": true}},
	  {"Type": "volume", "Target": "/cache", "VolumeOptions": {"NoCopy": false, "Labels": null, "DriverConfig": null}},
	  {"Type": "volume", "Source": "", "Target": "/cache2"},
	  {"Type": "tmpfs", "Target": "/tmp", "TmpfsOptions": {"SizeBytes": 67108864}}]}`)
	if r := h.request("POST", create, body); r.code != 201 {
		t.Fatal(r)
	}
}

func TestCLIAndComposeReadsPass(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, p := range []string{"/_ping", "/v1.52/version", "/v1.52/containers/palworld/json", "/v1.52/containers/" + palID[:12] + "/json",
		"/v1.52/containers/palworld/logs?stdout=1&stderr=1&tail=100", "/v1.52/containers/palworld/stats?stream=0",
		"/v1.52/containers/palworld/top?ps_args=-ef", "/v1.52/networks/crowsnest-games-net",
		"/v1.52/images/thijsvanloef/palworld-server-docker:latest/json"} {
		if r := h.request("GET", p, nil); r.code != 200 {
			t.Errorf("%s: %s", p, r)
		}
	}
	if r := h.request("HEAD", "/_ping", nil); r.code != 200 {
		t.Error(r)
	}
}

func TestStartStopRestartOnlyInScope(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, action := range []string{"start", "stop?t=300", "restart?t=10"} {
		if r := h.request("POST", "/v1.52/containers/palworld/"+action, nil); r.code != 204 {
			t.Errorf("%s: %s", action, r)
		}
	}
	h.eng.clear()
	rid := retiredID[:12]
	for _, p := range []string{"/containers/vaultwarden/stop", "/containers/" + vwID + "/start", "/containers/palworld/start?checkpoint=x&checkpoint-dir=/",
		"/containers/palworld/kill", "/containers/palworld/rename?name=x", "/containers/palworld/update",
		"/containers/" + vwID + "/rename?name=x", "/containers/palworld/rename?name=a1a1a1a1a1a1_palworld",
		"/containers/" + rid + "_valheim/rename?name=palworld", "/containers/" + rid + "_valheim/rename?name=x",
		"/containers/palworld/attach?stream=1", "/containers/palworld/archive"} {
		h.refused("POST", p, nil)
		if len(h.reached("POST", pathOf(p))) > 0 {
			t.Errorf("engine saw POST %s", p)
		}
	}
	for _, c := range [][2]string{{"DELETE", "/containers/vaultwarden"}, {"DELETE", "/images/x"}, {"DELETE", "/volumes/x"}, {"POST", "/networks/create"},
		{"POST", "/networks/x/connect"}, {"POST", "/volumes/create"}, {"POST", "/build"}, {"PUT", "/containers/palworld/archive"},
		{"GET", "/events"}, {"GET", "/containers/palworld/export"}, {"GET", "/containers/vaultwarden/json"},
		{"GET", "/containers/vaultwarden/logs"}, {"POST", "/containers/prune"}, {"GET", "/system/df"}} {
		r := h.refused(c[0], c[1], nil)
		if strings.Contains(string(r.raw), "vaultwarden/server") {
			t.Errorf("%v leaked: %s", c, r)
		}
		if !(c[0] == "GET" && strings.HasSuffix(c[1], "/json")) { // the guard's own lookup of the container uses that path
			if len(h.reached(c[0], pathOf(c[1]))) > 0 {
				t.Errorf("engine saw %v", c)
			}
		}
	}
}

// compose recreates a changed container: create the new one as <old id12>_<name>, remove the old, rename.
func TestRecreateStepsCreateRemoveAndRenameInScope(t *testing.T) {
	h := newHarness(t, scopesJSON)
	body := map[string]any{"Image": "lloesche/valheim-server", "HostConfig": map[string]any{"NetworkMode": "crowsnest-games-net"}}
	if r := h.request("POST", "/v1.52/containers/create?name="+valID[:12]+"_valheim", body); r.code != 201 {
		t.Fatal(r)
	}
	if r := h.request("DELETE", "/v1.52/containers/valheim", nil); r.code != 200 {
		t.Fatal(r)
	}
	if r := h.request("DELETE", "/v1.52/containers/valheim?v=false&force=false&link=false", nil); r.code != 200 {
		t.Fatal(r)
	}
	if r := h.request("POST", "/v1.52/containers/"+retiredID[:12]+"_valheim/rename?name=valheim", nil); r.code != 200 {
		t.Fatal(r)
	}
	if r := h.request("DELETE", "/v1.52/containers/"+retiredID[:12]+"_valheim?force=true", nil); r.code != 200 {
		t.Fatal(r)
	}
	// the engine is sent the full ids the checks resolved, and rename keeps the checked name
	if n := len(h.exactly("DELETE", "/containers/"+valID)); n != 2 {
		t.Fatalf("engine saw %d deletes of valheim by id, want 2: %v", n, h.eng.all())
	}
	if r := h.exactly("POST", "/containers/"+retiredID+"/rename"); len(r) != 1 || r[0].uri != "/v1.52/containers/"+retiredID+"/rename?name=valheim" {
		t.Fatalf("rename reached the engine as %v", r)
	}
	if n := len(h.exactly("DELETE", "/containers/"+retiredID)); n != 1 {
		t.Fatalf("engine saw %d deletes of the copy by id, want 1", n)
	}
	for _, s := range h.eng.all() {
		if s.method != "GET" && strings.Contains(s.path, "valheim") {
			t.Fatalf("engine was sent a name, not an id: %s %s", s.method, s.uri)
		}
	}
}

func TestRecreateNameMustFollowTheCurrentContainer(t *testing.T) {
	h := newHarness(t, scopesJSON)
	h.eng.clear()
	for _, name := range []string{"000000000000_valheim", "c3c3c3c3c3c3_vaultwarden", "c3c3c3c3c3c3_nosuch", "c3c3c3c3c3_valheim",
		"c3c3c3c3c3c3_valheim_x", "C3C3C3C3C3C3_valheim", "c3c3c3c3c3c3-valheim"} {
		h.refused("POST", "/containers/create?name="+name, map[string]any{"Image": "lloesche/valheim-server", "HostConfig": map[string]any{"NetworkMode": "crowsnest-games-net"}})
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw a create")
	}
}

// compose reads the replacement back after creating it, before it stops and deletes the old container.
func TestTheReplacementIsInspectableOnlyWhileItsOldContainerStands(t *testing.T) {
	h := newHarness(t, scopesJSON)
	tmp := valID[:12] + "_valheim"
	if r := h.request("GET", "/v1.52/containers/"+tmp+"/json", nil); r.code != 200 {
		t.Fatal(r)
	}
	if r := h.request("GET", "/v1.52/containers/"+strings.Repeat("f6", 32)+"/json", nil); r.code != 200 {
		t.Fatal(r)
	}
	h.eng.clear()
	for _, p := range []string{"/containers/" + tmp + "/logs", "/containers/" + tmp + "/top", "/containers/" + tmp + "/stats?stream=0",
		"/containers/" + retiredID[:12] + "_valheim/json", // not the id of the current valheim
		"/containers/" + vwID[:12] + "_valheim/json", "/containers/" + valID[:12] + "_vaultwarden/json"} {
		if r := h.request("GET", p, nil); r.code != 404 {
			t.Errorf("%s: %s", p, r)
		}
	}
	for _, s := range h.eng.all() {
		if strings.HasSuffix(s.path, "/logs") || strings.HasSuffix(s.path, "/top") || strings.HasSuffix(s.path, "/stats") {
			t.Errorf("engine saw %s", s.uri)
		}
	}
	// the listing never shows it
	r := h.request("GET", "/containers/json?all=1", nil)
	if strings.Contains(string(r.raw), tmp) {
		t.Error("the replacement is listed")
	}
}

func TestRemovalIsLimitedToStoppedScopeContainers(t *testing.T) {
	h := newHarness(t, scopesJSON)
	h.eng.clear()
	for _, p := range []string{"/containers/palworld", // running
		"/containers/valheim?v=true", "/containers/valheim?v=1", "/containers/valheim?link=true",
		"/containers/valheim?v=false&v=true", "/containers/valheim?x=1",
		"/containers/vaultwarden", "/containers/" + vwID, "/containers/nosuch", "/containers/ab_valheim",
		"/containers/valheim/", "/containers/" + palID[:12]} {
		h.refused("DELETE", p, nil)
		if len(h.reached("DELETE", pathOf(p))) > 0 {
			t.Errorf("engine saw DELETE %s", p)
		}
	}
	if len(h.eng.reached2("DELETE")) > 0 {
		t.Error("engine saw a DELETE")
	}
}

func (e *fakeEngine) reached2(method string) []seenReq {
	var out []seenReq
	for _, s := range e.all() {
		if s.method == method {
			out = append(out, s)
		}
	}
	return out
}

// `docker inspect NAME` tries container, image, network, volume, plugin and only moves on past a 404.
func TestMissingAndOutOfScopeObjectsAreNotFound(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, p := range []string{"/containers/palworld-not-created-yet/json", "/containers/vaultwarden/json", "/containers/vaultwarden/logs",
		"/volumes/palworld", "/plugins/palworld/json", "/networks/palworld", "/images/palworld/json"} {
		if r := h.request("GET", p, nil); r.code != 404 {
			t.Errorf("%s: %s", p, r)
		}
	}
	if r := h.request("POST", "/containers/vaultwarden/stop", nil); r.code != 404 {
		t.Error(r)
	}
	if len(h.reached("POST", "/containers/vaultwarden/stop")) > 0 || len(h.reached("GET", "/volumes/palworld")) > 0 {
		t.Error("engine saw a request it should not have")
	}
}

func TestPullOfScopeImages(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, q := range []string{"fromImage=docker.io%2Fthijsvanloef%2Fpalworld-server-docker&tag=latest",
		"fromImage=thijsvanloef%2Fpalworld-server-docker&tag=" + digest,
		"fromImage=index.docker.io%2Fthijsvanloef%2Fpalworld-server-docker%3Av1.2.3",
		"fromImage=thijsvanloef%2Fpalworld-server-docker&tag=latest&platform=linux%2Famd64"} {
		if r := h.request("POST", "/v1.52/images/create?"+q, nil); r.code != 200 {
			t.Errorf("%s: %s", q, r)
		}
	}
}

// ---------------------------------------------------------------- 1. request smuggling through the tunnel

func TestUpgradeHeaderDoesNotOpenATunnelPipelined(t *testing.T) {
	h := newHarness(t, scopesJSON)
	smuggle := append([]byte("GET /containers/palworld/json HTTP/1.1\r\nHost: x\r\nUpgrade: tcp\r\nConnection: Upgrade\r\n\r\n"), evilCreate...)
	out := string(h.raw(smuggle, time.Second, nil, 0))
	if !strings.Contains(out, "crowsnest-guard") || !strings.Contains(out, " 403 ") {
		t.Fatalf("pipelined create was not refused: %q", out)
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw the smuggled create")
	}
}

func TestUpgradeHeaderDoesNotOpenATunnelDelayed(t *testing.T) {
	h := newHarness(t, scopesJSON)
	out := string(h.raw([]byte("GET /containers/palworld/json HTTP/1.1\r\nHost: x\r\nUpgrade: tcp\r\nConnection: Upgrade\r\n\r\n"), ms(800), evilCreate, time.Second))
	if !strings.HasPrefix(out, "HTTP/1.1 200") {
		t.Fatalf("%q", out)
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw the smuggled create")
	}
}

func TestNothingIsRelayedAfterALogFollow(t *testing.T) {
	h := newHarness(t, scopesJSON)
	head := []byte("GET /containers/palworld/logs?follow=1&stdout=1 HTTP/1.1\r\nHost: x\r\nUpgrade: tcp\r\nConnection: Upgrade\r\n\r\n")
	out := h.raw(append(append([]byte{}, head...), evilCreate...), ms(1500), nil, 0)
	out2 := h.raw(head, ms(300), evilCreate, ms(1500))
	if !strings.Contains(string(out), "log line 0") && !strings.Contains(string(out2), "log line 0") {
		t.Fatalf("the log did not stream: %q %q", out, out2)
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw the smuggled create")
	}
	if !strings.Contains(h.logged(), "client sent data on a stream") {
		t.Errorf("no deny line for data on a stream: %q", h.logged())
	}
}

func TestLogFollowStreams(t *testing.T) {
	h := newHarness(t, scopesJSON)
	out := string(h.raw([]byte("GET /v1.52/containers/palworld/logs?follow=1&stdout=1&stderr=1 HTTP/1.1\r\nHost: x\r\n\r\n"), ms(2500), nil, 0))
	if !strings.HasPrefix(out, "HTTP/1.1 200") || !strings.Contains(out, "log line 19") {
		t.Fatalf("%q", out)
	}
	seen := h.exactly("GET", "/containers/"+palID+"/logs") // the stream goes out with the checked id too
	if len(seen) != 1 {
		t.Fatalf("engine saw %v", h.eng.all())
	}
	hdr := seen[0].header
	if hdr.Get("Connection") != "close" || hdr.Get("Upgrade") != "" {
		t.Fatalf("engine got %v", hdr)
	}
}

func TestExecHijackRelaysStdinAndStopsAtANonUpgradedAnswer(t *testing.T) {
	h := newHarness(t, scopesJSON)
	r := h.request("POST", "/containers/valheim/exec", map[string]any{"Cmd": []any{"status"}, "AttachStdout": true, "AttachStdin": true})
	if r.code != 201 || r.json().(map[string]any)["Id"] != execID {
		t.Fatal(r)
	}
	out := string(h.raw(post("/exec/"+execID+"/start", map[string]any{"Detach": false, "Tty": false}), ms(500), []byte("hello"), ms(500)))
	if !strings.Contains(out, "101 UPGRADED") || !strings.Contains(out, "echo:hello") {
		t.Fatalf("hijack: %q", out)
	}
	// a detached start is not hijacked: whatever follows on that connection must not reach the engine
	h.eng.clear()
	out = string(h.raw(append(post("/exec/"+execID+"/start", map[string]any{"Detach": true}), evilCreate...), time.Second, nil, 0))
	if !strings.HasPrefix(out, "HTTP/1.1 200") {
		t.Fatalf("detached start: %q", out)
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw the smuggled create")
	}
}

func TestChunkedAndFormBodiesAreRefused(t *testing.T) {
	h := newHarness(t, scopesJSON)
	out := h.raw([]byte("POST /containers/create?name=palworld HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"+
		"Content-Type: application/json\r\n\r\n5\r\n{\"a\":\r\n0\r\n\r\n"), ms(500), nil, 0)
	if !strings.HasPrefix(string(out), "HTTP/1.1 400") {
		t.Fatalf("chunked: %q", out)
	}
	form := "fromImage=&fromSrc=http%3A%2F%2Fevil%2Fx.tar&repo=thijsvanloef%2Fpalworld-server-docker&tag=latest"
	h.refused("POST", "/images/create?fromImage=thijsvanloef%2Fpalworld-server-docker&tag=latest", form,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if len(h.reached("POST", "/images/create")) > 0 || len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw a refused request")
	}
}

func TestUnusualRequestTargetsAreRefused(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, target := range []string{"http://docker/containers/palworld/json", "/containers/palworld/../vaultwarden/json", "/containers/palworld/json\x7f",
		"/containers/palworld/./json", "/containers/palworld/json/", "/containers/pal%77orld/json", "/containers/palworld/json?x=%zz"} {
		out := string(h.raw([]byte("GET "+target+" HTTP/1.1\r\nHost: x\r\n\r\n"), ms(500), nil, 0))
		if !strings.HasPrefix(out, "HTTP/1.1 400") {
			t.Errorf("%q: %q", target, out)
		}
	}
	if len(h.reached("GET", "/containers/vaultwarden/json")) > 0 {
		t.Fatal("engine saw vaultwarden")
	}
	// a doubled slash at the start is refused (Python's http.server folded it; here it is not a path we serve)
	out := string(h.raw([]byte("GET //v1.52/containers/palworld/json HTTP/1.1\r\nHost: x\r\n\r\n"), ms(500), nil, 0))
	if !strings.HasPrefix(out, "HTTP/1.1 400") {
		t.Errorf("%q", out)
	}
	for _, s := range h.eng.all() {
		if strings.HasPrefix(s.uri, "//") {
			t.Errorf("engine got %q", s.uri)
		}
	}
}

// ---------------------------------------------------------------- 2. create bodies: an allow-list

func TestDangerousHostConfigIsRefused(t *testing.T) {
	for i, host := range []string{
		`{"Mounts": [{"Type": "volume", "Source": "crowsnest-games_x", "Target": "/host", "VolumeOptions": {"DriverConfig": {"Name": "local", "Options": {"type": "none", "o": "bind", "device": "/"}}}}]}`,
		`{"Mounts": [{"Type": "volume", "Target": "/host", "VolumeOptions": {"DriverConfig": {"Name": "local", "Options": {"device": "/"}}}}]}`,
		`{"DeviceCgroupRules": ["b *:* rwm"]}`,
		`{"MaskedPaths": []}`,
		`{"ReadonlyPaths": []}`,
		`{"PortBindings": {"8212/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8212"}]}}`,
		`{"PortBindings": {"8211/udp": [{"HostIp": "", "HostPort": "8211"}]}}`,
		`{"PortBindings": {"8211/udp": [{"HostIp": "10.0.0.2", "HostPort": ""}]}}`,
		`{"PortBindings": {"8211/tcp": [{"HostIp": "10.0.0.2", "HostPort": "8211"}]}}`,
		`{"PortBindings": {"8211/udp": [{"HostIp": "10.0.0.2%eth0", "HostPort": "8211"}]}}`,
		`{"PublishAllPorts": true}`,
		`{"Binds": ["immich_pgdata:/steal"]}`,
		`{"Mounts": [{"Type": "volume", "Source": "immich_pgdata", "Target": "/steal"}]}`,
		`{"Sysctls": {"net.ipv4.ip_unprivileged_port_start": "0"}}`,
		`{"Runtime": "nvidia"}`,
		`{"CgroupParent": "/system.slice"}`,
		`{"OomKillDisable": true}`,
		`{"OomScoreAdj": -1000}`,
		`{"Privileged": true}`,
		`{"CapAdd": ["SYS_ADMIN"]}`,
		`{"Devices": [{"PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda", "CgroupPermissions": "rwm"}]}`,
		`{"DeviceRequests": [{"Driver": "nvidia", "Count": -1}]}`,
		`{"PidMode": "host"}`, `{"IpcMode": "host"}`, `{"UTSMode": "host"}`, `{"UsernsMode": "host"}`, `{"CgroupnsMode": "host"}`,
		`{"NetworkMode": "host"}`, `{"NetworkMode": "container:vaultwarden"}`, `{"NetworkMode": "bridge"}`, `{"NetworkMode": ""}`,
		`{"NetworkMode": "vaultwarden_default"}`, `{"NetworkMode": 5}`, `{"NetworkMode": ["crowsnest-games-net"]}`,
		`{"VolumesFrom": ["vaultwarden"]}`,
		`{"GroupAdd": ["988"]}`,
		`{"Links": ["vaultwarden:vw"]}`,
		`{"SecurityOpt": ["seccomp=unconfined"]}`, `{"SecurityOpt": ["apparmor=unconfined"]}`, `{"SecurityOpt": ["systempaths=unconfined"]}`,
		`{"SecurityOpt": ["label=disable"]}`, `{"SecurityOpt": ["no-new-privileges:false"]}`,
		`{"Ulimits": [{"Name": "memlock", "Soft": -1, "Hard": -1}]}`, `{"Ulimits": [null]}`,
		`{"LogConfig": {"Type": "syslog", "Config": {"syslog-address": "tcp://evil:514"}}}`,
		`{"Annotations": {"io.kubernetes.cri-o.Devices": "/dev/sda"}}`,
		`{"Binds": ["/:/host"]}`,
		`{"Binds": ["/var/run/docker.sock:/var/run/docker.sock"]}`,
		`{"Binds": ["PALDIR/../../../..:/host"]}`,
		`{"Binds": ["PALDIR/escape-symlink:/host"]}`, // exact path only: a symlink planted inside the bind is not followed
		`{"Binds": ["PALDIR/:/palworld"]}`,
		`{"Binds": ["/PALDIR:/palworld"]}`,
		`{"Binds": ["PALDIR-evil:/palworld"]}`,
		`{"Binds": ["PALDIR:/palworld:rshared"]}`,
		`{"Binds": ["PALDIR:/palworld:ro,rshared"]}`,
		`{"Binds": ["PALDIR"]}`, `{"Binds": ["PALDIR:/a:ro:x"]}`, `{"Binds": [5]}`, `{"Binds": "PALDIR:/palworld"}`,
		`{"Mounts": [{"Type": "bind", "Source": "/", "Target": "/host"}]}`,
		`{"Mounts": [{"Type": "bind", "Source": "PALDIR", "Target": "/p", "BindOptions": {"Propagation": "rshared"}}]}`,
		`{"Mounts": [{"Type": "image", "Source": "vaultwarden/server:latest", "Target": "/img"}]}`,
		`{"Mounts": [{"Type": "npipe", "Source": "x", "Target": "/x"}]}`,
		`{"Mounts": [{"Type": "bind", "Source": "PALDIR", "Target": "/p", "source": "/"}]}`, // Go would read the second key
		`{"Mounts": [{"Type": "bind", "Source": "PALDIR", "Target": "/p", "ImageOptions": {"Subpath": "x"}}]}`,
		`{"Mounts": [{"Type": "bind", "Source": "PALDIR", "Target": "relative"}]}`,
		`{"Mounts": [{"Type": "tmpfs", "Source": "/etc", "Target": "/t"}]}`,
		`{"Mounts": [{"Type": "volume", "Source": ["x"], "Target": "/v"}]}`,
		`{"Mounts": [{"Type": "volume", "Source": 0, "Target": "/v"}]}`,
		`{"Mounts": [{"Type": "volume", "Target": "/v", "VolumeOptions": {"Subpath": "../../etc"}}]}`,
		`{"Mounts": [{"Type": "volume", "Target": "/v", "VolumeOptions": {"Subpath": "/etc"}}]}`,
		// an auto-removed container leaves nothing to inspect: with a planted symlink and an entrypoint, a one-shot host write
		`{"AutoRemove": true}`,
		// "must be empty" is shallow: a list or map holding an empty entry is not empty to the engine
		`{"DeviceRequests": [{}]}`, `{"Sysctls": {"": ""}}`, `{"GroupAdd": [""]}`, `{"Devices": [{}]}`, `{"Links": [""]}`, `{"VolumesFrom": [""]}`,
		`{"BlkioWeightDevice": [{}]}`, `{"StorageOpt": {"": ""}}`, `{"Annotations": {"": ""}}`,
		`{"Mounts": [{"Type": "volume", "Target": "/v", "VolumeOptions": {"DriverConfig": {"Name": "local", "Options": {"": ""}}}}]}`,
		`{"Mounts": [{"Type": "volume", "Target": "/v", "VolumeOptions": {"DriverConfig": {"Name": "nfs"}}}]}`,
		`{"Mounts": [{"Type": "bind", "Source": "PALDIR", "Target": "/p", "VolumeOptions": [{}]}]}`,
		// shapes the checks did not foresee: refused, never passed on
		`{"PortBindings": {"8211/udp": [null]}}`, `{"PortBindings": {"8211/udp": ["10.0.0.2:8211"]}}`, `{"Mounts": [null]}`, `{"Mounts": {}}`,
		`{"PortBindings": []}`, `{"PortBindings": {"8211/udp": {}}}`, `{"PortBindings": {"x": []}}`,
		`{"Memory": 1.5}`, `{"Memory": 1e3}`, `{"Memory": -1}`, `{"Memory": true}`, `{"Memory": "1"}`,
		`{"privileged": true}`, // Go matches field names case-insensitively
		`{"Privileged": false, "privileged": true}`,
		`{"MaſkedPaths": []}`, // long s: Unicode case folding
		`{"SomeFutureField": []}`,
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			h := newHarness(t, scopesJSON)
			h.refused("POST", create, composeBody(t, host))
			if len(h.reached("POST", "/containers/create")) > 0 {
				t.Fatalf("engine saw the create of %s", host)
			}
		})
	}
}

func TestDangerousContainerSettingsAreRefused(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for i, change := range []string{
		`{"NetworkingConfig": {"EndpointsConfig": {"vaultwarden_default": {}}}}`,
		`{"NetworkingConfig": {"EndpointsConfig": {"crowsnest-games-net": {"IPAMConfig": {"IPv4Address": "172.30.0.3"}}}}}`,
		`{"NetworkingConfig": {"EndpointsConfig": {"crowsnest-games-net": {"DriverOpts": {"com.docker.network.endpoint.sysctls": "net.ipv4.conf.IFNAME.forwarding=1"}}}}}`,
		`{"NetworkingConfig": {"EndpointsConfig": {"crowsnest-games-net": {"MacAddress": "02:42:ac:11:00:02"}}}}`,
		`{"NetworkingConfig": {"EndpointsConfig": []}}`,
		`{"NetworkingConfig": []}`,
		`{"networkingconfig": {"EndpointsConfig": {"vaultwarden_default": {}}}}`,
		`{"hostconfig": {"Privileged": true}}`,
		`{"Image": "evil.example.com/thijsvanloef/palworld-server-docker:latest"}`,
		`{"Image": "thijsvanloef/palworld-server-docker-evil:latest"}`,
		`{"Image": "docker.io.evil.com/thijsvanloef/palworld-server-docker:latest"}`,
		`{"Image": "vaultwarden/server:latest"}`,
		`{"Image": "PALIMG"}`,
		`{"Image": null}`,
		`{"Image": 5}`,
		`{"Volumes": {"/host:/x": {}}}`,
		`{"Volumes": {"relative": {}}}`,
		`{"MacAddress": "02:42:ac:11:00:02"}`,
		`{"SomeNewField": ["x"]}`,
	} {
		body := composeBody(t)
		for k, v := range jv(t, change) {
			body[k] = v
		}
		h.refused("POST", create, body)
		if len(h.reached("POST", "/containers/create")) > 0 {
			t.Fatalf("case %d reached the engine: %s", i, change)
		}
	}
}

func TestCreateNeedsAScopeNameOnce(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, q := range []string{"name=vaultwarden", "name=evil", "", "name=palworld&name=evil", "name=palworld&extra=1", "name=palworld&platform=a&platform=b"} {
		h.refused("POST", "/containers/create?"+q, composeBody(t))
	}
	for _, raw := range []string{"not json", `{"Image": NaN}`, "[]", "null", `{"Image": "x"} {"y": 1}`, `{"a": 1, "A": 2}`, "\xff\xfe", `{"Image": "thijsvanloef/palworld-server-docker"`} {
		h.refused("POST", create, raw)
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw a create")
	}
}

func TestCreateWithDigestAndHubAliases(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, image := range []string{"thijsvanloef/palworld-server-docker@" + digest, "docker.io/thijsvanloef/palworld-server-docker:latest",
		"index.docker.io/thijsvanloef/palworld-server-docker:latest@" + digest, "thijsvanloef/palworld-server-docker"} {
		body := composeBody(t)
		body["Image"] = image
		if r := h.request("POST", create, body); r.code != 201 {
			t.Errorf("%s: %s", image, r)
		}
	}
}

func TestNetworksByFullIDAreResolved(t *testing.T) {
	h := newHarness(t, scopesJSON)
	body := composeBody(t, `{"NetworkMode": "NETID"}`)
	body["NetworkingConfig"] = jv(t, `{"EndpointsConfig": {"NETID": {"Aliases": ["palworld"]}}}`)
	if r := h.request("POST", create, body); r.code != 201 {
		t.Fatal(r)
	}
	h.eng.clear()
	for _, mode := range []string{otherNetID, netID[:12]} {
		h.refused("POST", create, composeBody(t, fmt.Sprintf(`{"NetworkMode": %q}`, mode)))
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw a create")
	}
}

func valheimBody(t testing.TB, hostJSON ...string) map[string]any {
	hosts := append([]string{`{"PortBindings": {}, "NetworkMode": "crowsnest-games-net", "Binds": ["/srv/valheim:/config"]}`}, hostJSON...)
	body := composeBody(t, hosts...)
	body["Image"] = "lloesche/valheim-server:latest"
	delete(body["Labels"].(map[string]any), "com.centurylinklabs.watchtower.enable") // not one of valheim's labels
	body["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)["crowsnest-games-net"].(map[string]any)["Aliases"] = []any{"valheim", "valheim-server"}
	return body
}

func TestNamedVolumesAndExactBindsWhenTheScopeAllowsThem(t *testing.T) {
	h := newHarness(t, scopesJSON)
	body := valheimBody(t, `{"Binds": ["crowsnest-games_saves:/saves", "/srv/valheim:/config", "/srv/valheim/backups:/backups:ro,z"]}`)
	if r := h.request("POST", "/containers/create?name=valheim", body); r.code != 201 {
		t.Fatal(r)
	}
	h.eng.clear()
	host := body["HostConfig"].(map[string]any)
	for _, binds := range []string{`["/srv/valheim/../palworld:/x"]`, `["PALDIR:/x"]`, // outside it / another scope's path
		`["/srv/valheim/config:/config"]`, `["/srv/valheim/backups/x:/x"]`} { // below a listed path: could be a planted symlink
		var v []any
		json.Unmarshal([]byte(strings.ReplaceAll(binds, "PALDIR", palDir)), &v)
		host["Binds"] = v
		h.refused("POST", "/containers/create?name=valheim", body)
	}
	host["Binds"] = nil
	host["Mounts"] = []any{map[string]any{"Type": "bind", "Source": "/srv/valheim/link", "Target": "/x"}}
	h.refused("POST", "/containers/create?name=valheim", body)
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw a create")
	}
}

// ---------------------------------------------------------------- 3. look-alike images

func TestLookAlikePullsAndImportsAreRefused(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, q := range []string{
		"fromImage=evil.example.com%2Fthijsvanloef%2Fpalworld-server-docker&tag=latest",
		"fromImage=thijsvanloef%2Fpalworld-server-docker-evil&tag=latest",
		"fromImage=docker.io.evil.com%2Fthijsvanloef%2Fpalworld-server-docker&tag=latest",
		"fromImage=localhost%3A5000%2Fthijsvanloef%2Fpalworld-server-docker&tag=latest",
		"fromImage=THIJSVANLOEF%2Fpalworld-server-docker&tag=latest",
		"fromImage=thijsvanloef%2Fpalworld-server-docker", // every tag
		"fromImage=thijsvanloef%2Fpalworld-server-docker%3Alatest&tag=other",
		"fromImage=&fromImage=thijsvanloef%2Fpalworld-server-docker&fromSrc=-&repo=thijsvanloef%2Fpalworld-server-docker&tag=latest",
		"fromSrc=-&repo=thijsvanloef%2Fpalworld-server-docker&tag=latest",
		"fromImage=thijsvanloef%2Fpalworld-server-docker&tag=latest&fromSrc=http%3A%2F%2Fevil%2Fx.tar",
		"fromImage=thijsvanloef%2Fpalworld-server-docker&tag=latest&tag=evil",
		"fromImage=thijsvanloef%2Fpalworld-server-docker&tag=..%2F..",
		"fromImage=thijsvanloef%2Fpalworld-server-docker&tag=latest&message=x",
	} {
		h.refused("POST", "/images/create?"+q, nil)
		if len(h.reached("POST", "/images/create")) > 0 {
			t.Fatalf("engine saw the pull %s", q)
		}
	}
}

func TestImageReferencesAreNormalised(t *testing.T) {
	for ref, repo := range map[string]string{
		"palworld": "docker.io/library/palworld",
		"thijsvanloef/palworld-server-docker:latest":               "docker.io/thijsvanloef/palworld-server-docker",
		"registry-1.docker.io/thijsvanloef/palworld-server-docker": "docker.io/thijsvanloef/palworld-server-docker",
		"index.docker.io/library/ubuntu:24.04":                     "docker.io/library/ubuntu",
		"ghcr.io/org/app@" + digest:                                "ghcr.io/org/app",
		"localhost:5000/app:1":                                     "localhost:5000/app",
		"Registry.Example.com/app":                                 "registry.example.com/app",
	} {
		got, _, _, err := parseRef(ref)
		if err != nil || got != repo {
			t.Errorf("parseRef(%q) = %q, %v; want %q", ref, got, err, repo)
		}
	}
}

func TestBadImageReferences(t *testing.T) {
	for _, ref := range []string{"", "upper/CASE", "a//b", "app@sha256:short", "app:bad tag", "/abs", "app:", "a/b:" + strings.Repeat("x", 129)} {
		if _, _, _, err := parseRef(ref); err == nil {
			t.Errorf("parseRef(%q) accepted", ref)
		}
	}
}

// ---------------------------------------------------------------- 4. exec

func TestExecIsOffUnlessTheScopeEnablesIt(t *testing.T) {
	h := newHarness(t, scopesJSON)
	h.refused("POST", "/containers/palworld/exec", map[string]any{"Cmd": []any{"sh"}})
	if len(h.reached("POST", "/containers/palworld/exec")) > 0 {
		t.Fatal("engine saw the exec")
	}
}

func TestExecBodiesAreChecked(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, body := range []string{`{"Cmd": ["sh"], "Privileged": true}`, `{"Cmd": ["sh"], "User": "root"}`, `{"Cmd": ["sh"], "User": "0:0"}`,
		`{"Cmd": ["sh"], "privileged": true}`, `{"Cmd": ["sh"], "Privileged": false, "privileged": true}`, `{"Cmd": []}`, `{"Cmd": [1]}`, `{}`,
		`not a dict`, `{"Cmd": ["sh"], "Mounts": [1]}`, `{"Cmd": ["sh"], "Env": [1]}`} {
		h.refused("POST", "/containers/valheim/exec", body)
	}
	h.refused("POST", "/containers/valheim/exec?x=1", `{"Cmd": ["sh"]}`)
	h.refused("POST", "/containers/valheim/exec", nil)
	if len(h.reached("POST", "/containers/valheim/exec")) > 0 {
		t.Fatal("engine saw an exec")
	}
}

func TestExecIDsMustComeFromThisGuard(t *testing.T) {
	h := newHarness(t, scopesJSON)
	zero := strings.Repeat("00", 32)
	for _, c := range [][2]string{{"POST", "/exec/" + zero + "/start"}, {"POST", "/exec/" + zero + "/resize?h=1&w=1"}, {"GET", "/exec/" + zero + "/json"}} {
		var body any
		if c[0] == "POST" {
			body = map[string]any{}
		}
		h.refused(c[0], c[1], body)
		if len(h.reached(c[0], pathOf(c[1]))) > 0 {
			t.Errorf("engine saw %v", c)
		}
	}
	if r := h.request("POST", "/containers/valheim/exec", map[string]any{"Cmd": []any{"status"}, "User": "", "Privileged": false}); r.code != 201 {
		t.Fatal(r)
	}
	if r := h.request("GET", "/exec/"+execID+"/json", nil); r.code != 200 {
		t.Error(r)
	}
	if r := h.request("POST", "/exec/"+execID+"/resize?h=24&w=80", nil); r.code != 200 {
		t.Error(r)
	}
	h.refused("POST", "/exec/"+execID+"/resize?h=24&w=80&x=1", nil)
	h.refused("POST", "/exec/"+execID+"/start", map[string]any{"Detach": true, "Env": []any{"A=1"}})
	h.refused("POST", "/exec/"+execID+"/start?x=1", map[string]any{"Detach": true})
}

// ---------------------------------------------------------------- 6. visibility

func TestContainerListIsFilteredButKeepsTheQuery(t *testing.T) {
	h := newHarness(t, scopesJSON)
	flt := `{"label":["com.docker.compose.project=crowsnest-games"]}`
	r := h.request("GET", "/v1.52/containers/json?all=1&filters="+url.QueryEscape(flt), nil)
	if r.code != 200 {
		t.Fatal(r)
	}
	var names []string
	for _, c := range r.json().([]any) {
		names = append(names, c.(map[string]any)["Names"].([]any)[0].(string))
	}
	if strings.Join(names, ",") != "/palworld,/valheim" {
		t.Fatalf("names = %v", names)
	}
	if got := h.reached("GET", "/containers/json")[0].q["filters"]; len(got) != 1 || got[0] != flt {
		t.Fatalf("engine got filters %v", got)
	}
}

func TestImageListAndInspectAreFiltered(t *testing.T) {
	h := newHarness(t, scopesJSON)
	r := h.request("GET", "/images/json", nil)
	l, _ := r.json().([]any)
	if r.code != 200 || len(l) != 1 || l[0].(map[string]any)["Id"] != palImageID {
		t.Fatal(r)
	}
	if r := h.request("GET", "/images/"+palImageID+"/json", nil); r.code != 200 {
		t.Error(r)
	}
	for _, ref := range []string{"evil.example.com/thijsvanloef/palworld-server-docker:latest", "vaultwarden/server:latest", "sha256:" + strings.Repeat("02", 32)} {
		if r := h.request("GET", "/images/"+ref+"/json", nil); r.code != 404 {
			t.Errorf("%s: %s", ref, r)
		}
	}
}

func TestNetworkListAndInspectAreFiltered(t *testing.T) {
	h := newHarness(t, scopesJSON)
	r := h.request("GET", "/networks?filters="+url.QueryEscape(`{"name":{"crowsnest-games-net":true}}`), nil)
	l, _ := r.json().([]any)
	if r.code != 200 || len(l) != 1 || l[0].(map[string]any)["Name"] != "crowsnest-games-net" {
		t.Fatal(r)
	}
	// the list too only names the scope's own containers
	if cs := l[0].(map[string]any)["Containers"].(map[string]any); len(cs) != 1 || cs[palID] == nil {
		t.Errorf("list containers = %v", cs)
	}
	for _, ref := range []string{"crowsnest-games-net", netID, netID[:12]} {
		r := h.request("GET", "/networks/"+ref, nil)
		net, _ := r.json().(map[string]any)
		cs, _ := net["Containers"].(map[string]any)
		if r.code != 200 || len(cs) != 1 || cs[palID] == nil {
			t.Errorf("%s: %s", ref, r)
		}
	}
	for _, ref := range []string{"vaultwarden_default", otherNetID, "bridge"} {
		if r := h.request("GET", "/networks/"+ref, nil); r.code != 404 {
			t.Errorf("%s: %s", ref, r)
		}
	}
}

func TestVolumesAreFilteredToTheScopePrefixes(t *testing.T) {
	h := newHarness(t, scopesJSON)
	r := h.request("GET", "/volumes", nil)
	vols := r.json().(map[string]any)["Volumes"].([]any)
	if r.code != 200 || len(vols) != 1 || vols[0].(map[string]any)["Name"] != "crowsnest-games_saves" {
		t.Fatal(r)
	}
	if r := h.request("GET", "/volumes/crowsnest-games_saves", nil); r.code != 200 {
		t.Error(r)
	}
	h.refused("GET", "/volumes/immich_pgdata", nil)
	if len(h.reached("GET", "/volumes/immich_pgdata")) > 0 {
		t.Error("engine saw the volume")
	}
}

func TestInfoIsRedacted(t *testing.T) {
	h := newHarness(t, scopesJSON)
	r := h.request("GET", "/v1.52/info", nil)
	got, _ := r.json().(map[string]any)
	if r.code != 200 || got["ServerVersion"] != "29.0.1" || got["OSType"] != "linux" || got["Driver"] != "overlay2" {
		t.Fatal(r)
	}
	if got["Swarm"].(map[string]any)["LocalNodeState"] != "inactive" || len(got["Warnings"].([]any)) != 0 {
		t.Error("swarm or warnings not reduced")
	}
	for _, secret := range []string{"HOST-ID", "my-secret-hostname", "proxy", "/var/lib/docker", "owner=plex", "mirror.internal", "node-secret", "47"} {
		if strings.Contains(string(r.raw), secret) {
			t.Errorf("info leaks %q", secret)
		}
	}
}

func TestBodiesOnOtherRequestsAreRefused(t *testing.T) {
	h := newHarness(t, scopesJSON)
	h.refused("POST", "/containers/palworld/start", map[string]any{"x": 1})
	h.refused("GET", "/containers/json", "x=1")
	if len(h.reached("POST", "/containers/palworld/start")) > 0 {
		t.Fatal("engine saw the start")
	}
}

// ---------------------------------------------------------------- 5. configuration

func TestBadConfigurationIsRefused(t *testing.T) {
	for i, env := range []string{
		``, `not json`, `[]`, `{"name": "game"}`,
		`[{"name": "game"}]`,                           // no images
		`[{"name": "game", "images": ["a/b:latest"]}]`, // tag in an allow-list
		`[{"name": "game", "images": ["a/b@` + digest + `"]}]`,
		`[{"name": "game", "images": ["a/b"], "binds": ["relative"]}]`,
		`[{"name": "game", "images": ["a/b"], "binds": ["/"]}]`,
		`[{"name": "game", "images": ["a/b"], "binds": ["/srv/../etc"]}]`,
		`[{"name": "game", "images": ["a/b"], "binds": ["/srv/x/"]}]`,
		`[{"name": "game", "images": ["a/b"], "binds": ["/srv/a:b"]}]`,
		`[{"name": "game", "images": ["a/b"], "binds": [{"path": "/srv/x", "subpaths": true}]}]`, // gone: symlinks
		`[{"name": "game", "images": ["a/b"], "labels": ["traefik.enable"]}]`,
		`[{"name": "game", "images": ["a/b"], "labels": {"traefik.enable": true}}]`,
		`[{"name": "game", "images": ["a/b"], "labels": null}]`,
		`[{"name": "game", "images": ["a/b"], "aliases": ["bad alias"]}]`,
		`[{"name": "game", "images": ["a/b"], "network": ["host"]}]`, // typo: unknown key
		`[{"name": "game", "images": ["a/b"], "networks": ["container:y"]}]`,
		`[{"name": "game", "images": ["a/b"], "networks": null}]`,
		`[{"name": "game", "images": ["a/b"], "ports": [{"host_ip": "", "host_port": "1"}]}]`,
		`[{"name": "game", "images": ["a/b"], "ports": [{"host_ip": "10.0.0.2", "host_port": "99999"}]}]`,
		`[{"name": "game", "images": ["a/b"], "ports": [{"host_ip": "10.0.0.2", "host_port": "0"}]}]`,
		`[{"name": "game", "images": ["a/b"], "ports": [{"host_ip": "10.0.0.2", "host_port": 8211.5}]}]`,
		`[{"name": "game", "images": ["a/b"], "ports": [{"host_ip": "10.0.0.2"}]}]`,
		`[{"name": "game", "images": ["a/b"], "ports": [{"host_ip": 5, "host_port": "1"}]}]`,
		`[{"name": "game", "images": ["a/b"], "ports": [{"host_ip": "10.0.0.2", "host_port": "1", "proto": "icmp"}]}]`,
		`[{"name": "game", "images": ["a/b"], "ports": [{"host_ip": "10.0.0.2", "host_port": "1", "extra": 1}]}]`,
		`[{"name": "game", "images": ["a/b"], "exec": "yes"}]`,
		`[{"name": "game", "images": ["a/b"], "cap_add": ["ALL"]}]`,
		`[{"name": "game", "images": ["a/b"], "secopts": [""]}]`,
		`[{"name": "g", "images": ["a/b"]}]`, // names are two characters or more
		`[{"name": "game", "images": ["a/b"]}, {"name": "game", "images": ["a/c"]}]`,
		`[{"name": "game", "Name": "x", "images": ["a/b"]}]`,
		`[{"name": "game", "images": ["a/b"], "images": ["a/c"]}]`, // duplicate key
		`[{"name": "game", "images": ["a/b"]}] trailing`,
	} {
		if _, err := LoadScopes(env); err == nil {
			t.Errorf("case %d accepted: %s", i, env)
		}
	}
}

func TestValidConfiguration(t *testing.T) {
	sc, err := LoadScopes(scopesJSON)
	if err != nil || len(sc) != 2 {
		t.Fatal(err)
	}
	pal := sc[0]
	if !pal.Images["docker.io/thijsvanloef/palworld-server-docker"] || pal.Exec || len(pal.Networks) != 1 || pal.Ports[0] != (Port{"10.0.0.2", "8211", "", "udp"}) {
		t.Errorf("%+v", pal)
	}
	if !pal.bindOK(palDir) || pal.bindOK(palDir+"/sub") || pal.bindOK("/") {
		t.Error("binds are exact paths")
	}
	if !sc[1].Exec || !sc[1].volumeOK("crowsnest-games_x") || sc[1].volumeOK("other_x") {
		t.Errorf("%+v", sc[1])
	}
	// the deployed shape: several scopes, host networking and seccomp spelled out, ports as numbers
	if _, err := LoadScopes(`[{"name": "windrose", "images": ["indifferentbroccoli/windrose-server-docker"], "binds": ["/srv/w"],
	  "networks": ["host"], "secopts": ["seccomp=unconfined", "seccomp:unconfined"], "ports": [{"host_ip": "10.0.0.2", "host_port": 2456, "container_port": 2456, "proto": "udp"}],
	  "labels": {"a": "b"}, "exec": true, "cap_add": ["cap_net_admin"]}]`); err != nil {
		t.Error(err)
	}
}

func TestWindroseStyleScopeMustSpellOutHostNetworkingSeccompAndExec(t *testing.T) {
	windrose := `[{"name": "windrose", "images": ["example/windrose"], "binds": ["/srv/windrose"], "networks": ["host"],
	  "secopts": ["seccomp=unconfined"], "exec": true}]`
	h := newHarness(t, windrose)
	body := composeBody(t, `{"NetworkMode": "host", "PortBindings": {}, "Binds": ["/srv/windrose:/data"], "SecurityOpt": ["seccomp=unconfined"]}`)
	body["Image"], body["NetworkingConfig"] = "example/windrose:latest", nil
	delete(body["Labels"].(map[string]any), "com.centurylinklabs.watchtower.enable")
	if r := h.request("POST", "/containers/create?name=windrose", body); r.code != 201 {
		t.Fatal(r)
	}
	without := newHarness(t, `[{"name": "windrose", "images": ["example/windrose"], "binds": ["/srv/windrose"], "exec": true}]`)
	without.refused("POST", "/containers/create?name=windrose", body)
	body["HostConfig"].(map[string]any)["NetworkMode"] = "default"
	without.refused("POST", "/containers/create?name=windrose", body) // still the seccomp option
	if len(without.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw a create")
	}
}

// ---------------------------------------------------------------- the request plumbing

func TestStrictJSON(t *testing.T) {
	if _, err := strictJSON([]byte(`{"a": {"b": 1}, "c": [1, {"d": 2}]}`)); err != nil {
		t.Error(err)
	}
	for _, raw := range []string{`{"a": 1, "a": 2}`, `{"Source": 1, "source": 2}`, `{"x": {"Mounts": 1, "MOUNTS": 2}}`, `{"a": Infinity}`, `{"a": NaN}`,
		`{"ſ": 1, "S": 2}`, `{"K": 1, "k": 2}`, `{"a": 1} {"b": 2}`, ``, `{"a": 1,}`, "\"\xff\"", strings.Repeat("[", 40) + strings.Repeat("]", 40),
		strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40), strings.Repeat("[", 200000) + strings.Repeat("]", 200000)} {
		if _, err := strictJSON([]byte(raw)); err == nil {
			t.Errorf("accepted %.60q", raw)
		}
	}
}

func TestComposeBodyIsNotMutatedBetweenTests(t *testing.T) {
	a, _ := json.Marshal(composeBody(t))
	b, _ := json.Marshal(composeBody(t))
	if string(a) != string(b) {
		t.Fatal("composeBody differs between calls")
	}
}

func TestBitsOfTheConfigAreNotTheRequestPath(t *testing.T) {
	// the guard's startup refuses to list a scope-less, port-less or tag-carrying configuration (see TestBadConfigurationIsRefused);
	// and a body naming a field twice by case folding never reaches the checks
	h := newHarness(t, scopesJSON)
	h.refused("POST", create, `{"Image": "thijsvanloef/palworld-server-docker", "image": "alpine"}`)
}

// ---------------------------------------------------------------- red-team follow-up

func TestLabelsAreComposeBookkeepingAndTheScopeList(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, lbl := range []string{
		`{"traefik.enable": "true", "traefik.http.routers.x.rule": "Host(` + "`vault.example.com`" + `)"}`, // a proxy takes its routes from labels
		`{"ofelia.enabled": "true", "ofelia.job-exec.x.command": "sh -c evil"}`,                            // a job runner takes its jobs
		`{"com.centurylinklabs.watchtower.enable": "true"}`,                                                // listed, but with another value
		`{"com.centurylinklabs.watchtower.lifecycle.pre-update": "sh -c evil"}`,
		`{"Com.docker.compose.project": "x"}`,
		`{"x": 1}`,
	} {
		body := composeBody(t)
		for k, v := range jv(t, lbl) {
			body["Labels"].(map[string]any)[k] = v
		}
		h.refused("POST", create, body)
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw a create")
	}
}

func TestNetworkNamesAndAddressesStayTheScopesOwn(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, ep := range []string{
		`{"Aliases": ["palworld", "vaultwarden"]}`,                                                                   // would answer for another service on the shared network
		`{"Aliases": ["crowsnest"]}`, `{"DNSNames": ["palworld", "vaultwarden"]}`, `{"Aliases": ["valheim-server"]}`, // valheim's, not ours
		`{"IPAMConfig": {"IPv4Address": "172.30.0.3"}}`, // vaultwarden's address
		`{"IPAMConfig": {"IPv4Address": "", "LinkLocalIPs": [""]}}`, `{"DriverOpts": {"": ""}}`, `{"Links": [""]}`,
		`{"GwPriority": 1.5}`,
	} {
		body := composeBody(t)
		e := body["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)["crowsnest-games-net"].(map[string]any)
		for k, v := range jv(t, ep) {
			e[k] = v
		}
		h.refused("POST", create, body)
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw a create")
	}
}

func TestComposeAliasesAndDNSNamesAreAllowed(t *testing.T) {
	h := newHarness(t, scopesJSON)
	body := composeBody(t)
	e := body["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)["crowsnest-games-net"].(map[string]any)
	e["Aliases"], e["DNSNames"] = []any{"palworld", "palworld"}, []any{"palworld"}
	if r := h.request("POST", create, body); r.code != 201 {
		t.Fatal(r)
	}
	if r := h.request("POST", "/containers/create?name=valheim", valheimBody(t)); r.code != 201 {
		t.Fatal(r)
	}
}

func TestRequestTargetsTheEngineCouldReadDifferentlyAreRefused(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, target := range []string{
		// "#" ends the target for some parsers but not for Go's: the parameters after it would reach the engine unchecked
		"/v1.52/containers/palworld/start?#&checkpoint=x&checkpoint-dir=/",
		"/v1.52/containers/palworld/top?ps_args=-ef#&ps_args=;id",
		"/v1.52/containers/palworld/logs?#&follow=1",
		"/v1.52/images/create?fromImage=thijsvanloef%2Fpalworld-server-docker&tag=latest#&fromImage=evil%2Fx",
		"/v1.52/containers/palworld/json;x", "/v1.52/containers/palworld/logs?stdout=1;follow=1",
		"/v1.52/containers/palworld/json\xc3\xa9", "/v\xd9\xa1.\xd9\xa5\xd9\xa2/containers/palworld/json", // raw bytes, Arabic digits
		"/v1.40/containers/palworld/json", "/v1.43/containers/palworld/json", "/v1/containers/palworld/json",
		"/v1.52.1/containers/palworld/json", "/v01.0052x/containers/palworld/json", "/v.52/containers/palworld/json",
		"/v1.52/containers/palworld/json\x01", "/v1.52/containers/palworld/json\x7f", "/v1.0052345/containers/palworld/json",
		"/v1.52/containers/palworld%2Fjson", "/v1.52/containers/palworld/%6Ason",
	} {
		out := string(h.raw([]byte("POST "+target+" HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"), ms(400), nil, 0))
		if !strings.HasPrefix(out, "HTTP/1.1 400") && !strings.HasPrefix(out, "HTTP/1.1 403") {
			t.Errorf("%q: %.100q", target, out)
		}
	}
	if n := len(h.eng.all()); n != 0 {
		t.Fatalf("engine saw %d requests", n)
	}
}

func TestTheEngineGetsTheTargetTheChecksRead(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, p := range []string{"/v1.52/containers/palworld/top?ps_args=%2Def", "/v1.52/containers/palworld/logs?stdout=1&tail=1%30&since=",
		"/containers/palworld/logs?tail=3", "/v01.052/containers/palworld/top?ps_args=a+b"} {
		if r := h.request("GET", p, nil); r.code != 200 {
			t.Fatalf("%s: %s", p, r)
		}
	}
	var targets []string
	for _, s := range h.eng.all() {
		if s.path != "/containers/palworld/json" {
			targets = append(targets, s.uri)
		}
	}
	// the ref the checks resolved, palworld, reaches the engine as the full id it resolved to
	want := []string{"/v1.52/containers/" + palID + "/top?ps_args=-ef", "/v1.52/containers/" + palID + "/logs?stdout=1&tail=10&since=",
		"/containers/" + palID + "/logs?tail=3", "/v1.52/containers/" + palID + "/top?ps_args=a+b"}
	if strings.Join(targets, "\n") != strings.Join(want, "\n") {
		t.Fatalf("engine got\n%s\nwant\n%s", strings.Join(targets, "\n"), strings.Join(want, "\n"))
	}
}

func TestStreamsAreClassifiedAsTheEngineReadsTheFlags(t *testing.T) {
	for _, c := range []struct {
		value  string
		set    bool
		follow bool
	}{{"1", true, true}, {"true", true, true}, {"TRUE", true, true}, {"yes", true, true}, {"2", true, true}, {" true ", true, true},
		{"0", true, false}, {"false", true, false}, {"FALSE", true, false}, {"no", true, false}, {"none", true, false}, {"", true, false}, {"", false, false}} {
		q := query{vals: map[string][]string{}}
		if c.set {
			q.vals["follow"] = []string{c.value}
		}
		if got := streamKind("/containers/palworld/logs", q) == "oneway"; got != c.follow {
			t.Errorf("logs follow=%q (set %v): oneway = %v", c.value, c.set, got)
		}
		q = query{vals: map[string][]string{}}
		if c.set {
			q.vals["stream"] = []string{c.value}
		}
		if got := streamKind("/containers/palworld/stats", q) == "oneway"; got != (c.follow || !c.set) { // stats streams by default
			t.Errorf("stats stream=%q (set %v): oneway = %v", c.value, c.set, got)
		}
	}
	if streamKind("/exec/abc/start", query{}) != "hijack" || streamKind("/containers/palworld/json", query{}) != "" {
		t.Error("exec start hijacks, inspects do not stream")
	}
}

func TestLogFollowInAnySpellingStreamsAndRelaysNothingBack(t *testing.T) {
	h := newHarness(t, scopesJSON)
	out := string(h.raw([]byte("GET /v1.52/containers/palworld/logs?follow=TRUE&stdout=1 HTTP/1.1\r\nHost: x\r\n\r\n"), ms(400), evilCreate, ms(500)))
	if !strings.Contains(out, "log line 0") || len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatalf("%q", out)
	}
}

func TestLargeBufferedAnswersAreRefused(t *testing.T) {
	h := newHarness(t, scopesJSON, func(g *Guard) { g.MaxResponse = 1000 })
	if r := h.request("GET", "/v1.52/containers/palworld/logs?stdout=1&tail=all", nil); r.code != 502 {
		t.Errorf("big answer: %s", r)
	}
	if r := h.request("GET", "/v1.52/containers/palworld/logs?stdout=1&tail=5", nil); r.code != 200 {
		t.Errorf("small answer: %s", r)
	}
}

func TestContentTypeIsSetHere(t *testing.T) {
	h := newHarness(t, scopesJSON)
	raw, _ := json.Marshal(composeBody(t))
	for _, extra := range []string{"Content-Type: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\n",
		"Content-Type: application/json\r\ncontent-type: application/json\r\n",
		"Content-Type: application/json\r\n X-Folded: application/x-www-form-urlencoded\r\n",
		"Content-Type: application/json\r\nX-Registry-Auth: a\r\n\tb\r\n",
		"Content-Type: application/json\r\nContent-Length: 5\r\n",
		"Content-Type: application/json\r\nExpect: 100-continue\r\n",
		"Content-Type: application/json\r\nX-Bad: a\x01b\r\n",
		"Content-Type: application/json\r\nX-Bad : a\r\n"} {
		out := string(h.raw([]byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: x\r\n%sContent-Length: %d\r\n\r\n%s", create, extra, len(raw), raw)), ms(400), nil, 0))
		if !strings.HasPrefix(out, "HTTP/1.1 400") {
			t.Errorf("%q: %.100q", extra, out)
		}
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw a create")
	}
	for _, ct := range []string{"application/json; charset=utf-8", "text/plain", "Application/JSON"} {
		if r := h.request("POST", create, composeBody(t), map[string]string{"Content-Type": ct}); r.code != 201 {
			t.Errorf("%s: %s", ct, r)
		}
	}
	sent := h.reached("POST", "/containers/create")
	if len(sent) != 3 {
		t.Fatalf("engine saw %d creates", len(sent))
	}
	for _, s := range sent {
		if s.header.Get("Content-Type") != "application/json" {
			t.Errorf("engine got Content-Type %q", s.header.Get("Content-Type"))
		}
	}
	h.refused("POST", "/v1.52/containers/palworld/start", nil, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
}

func TestDeepJSONIsRefused(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, raw := range []string{strings.Repeat("[", 40) + strings.Repeat("]", 40), strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40),
		strings.Repeat("[", 200000) + strings.Repeat("]", 200000)} {
		if r := h.request("POST", create, raw); r.code != 400 {
			t.Errorf("%.30q: %s", raw, r)
		}
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw a create")
	}
}

func TestACheckThatFailsUnexpectedlyRefuses(t *testing.T) {
	h := newHarness(t, scopesJSON, func(g *Guard) { g.SetScopes([]*Scope{nil}) }) // a nil scope: the pull check dereferences it
	r := h.request("POST", "/v1.52/images/create?fromImage=thijsvanloef%2Fpalworld-server-docker&tag=latest", nil)
	if r.code != 400 {
		t.Fatalf("%s", r)
	}
	if len(h.reached("POST", "/images/create")) > 0 {
		t.Fatal("engine saw the pull")
	}
	if !strings.Contains(h.logged(), "DENY POST /v1.52/images/create: internal error") {
		t.Errorf("log: %q", h.logged())
	}
}

func TestExecIDsAreBounded(t *testing.T) {
	g := New("/nonexistent", nil)
	for i := 0; i < 300; i++ {
		g.rememberExec(fmt.Sprintf("%064x", i))
	}
	if len(g.execSet) != execsKept || g.knownExec(fmt.Sprintf("%064x", 0)) || !g.knownExec(fmt.Sprintf("%064x", 299)) {
		t.Fatalf("kept %d; first known %v, last known %v", len(g.execSet), g.knownExec(fmt.Sprintf("%064x", 0)), g.knownExec(fmt.Sprintf("%064x", 299)))
	}
}

func TestConnectionsAreCapped(t *testing.T) {
	h := newHarness(t, scopesJSON, func(g *Guard) { g.MaxConns = 2 })
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", h.addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	time.Sleep(200 * time.Millisecond)
	extra, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	if out := string(drain(extra, time.Second)); !strings.HasPrefix(out, "HTTP/1.1 503") {
		t.Errorf("over the limit: %q", out)
	}
	extra.Close()
	held[0].Close()
	time.Sleep(300 * time.Millisecond) // its slot comes back
	if r := h.request("GET", "/_ping", nil); r.code != 200 {
		t.Errorf("after a slot freed: %s", r)
	}
	held[1].Close()
}

func TestARequestMustArriveWithinItsDeadline(t *testing.T) {
	h := newHarness(t, scopesJSON, func(g *Guard) { g.requestDeadline = 500 * time.Millisecond })
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	closed := false
	for _, b := range []byte("GET /v1.52/containers/palworld/json HTTP/1.1\r\nHost: x\r\nX-Slow: " + strings.Repeat("a", 40)) { // a byte every 0.05 s
		if _, err := c.Write([]byte{b}); err != nil {
			closed = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !closed {
		c.SetReadDeadline(time.Now().Add(time.Second))
		_, err := c.Read(make([]byte, 100))
		closed = err != nil
	}
	c.Close()
	if !closed || time.Since(start) > 4*time.Second {
		t.Fatal("a slow request was not cut off")
	}
	if len(h.reached("GET", "/containers/palworld/json")) > 0 {
		t.Fatal("engine saw the slow request")
	}
	c, err = net.Dial("tcp", h.addr) // idle before a request is not slow: the deadline starts later
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(800 * time.Millisecond)
	c.Write([]byte("GET /_ping HTTP/1.1\r\nHost: x\r\n\r\n"))
	if out := string(drain(c, 500*time.Millisecond)); !strings.HasPrefix(out, "HTTP/1.1 200") {
		t.Fatalf("%q", out)
	}
}

func TestKeepAliveServesSeveralRequests(t *testing.T) {
	h := newHarness(t, scopesJSON)
	two := "GET /_ping HTTP/1.1\r\nHost: x\r\n\r\nGET /v1.52/containers/palworld/json HTTP/1.1\r\nHost: x\r\n\r\n"
	out := string(h.raw([]byte(two), ms(500), nil, 0))
	if strings.Count(out, "HTTP/1.1 200") != 2 {
		t.Fatalf("%q", out)
	}
}

func TestDenyLogLine(t *testing.T) {
	h := newHarness(t, scopesJSON)
	h.refused("POST", "/v1.52/containers/palworld/kill", nil)
	h.refused("GET", "/containers/vaultwarden/json?x=1", nil)
	if got := h.logged(); !strings.Contains(got, "DENY POST /v1.52/containers/palworld/kill: write not allowed") ||
		!strings.Contains(got, `DENY GET /containers/vaultwarden/json: No such container: "vaultwarden"`) {
		t.Fatalf("log = %q", got)
	}
}

func TestConcurrentRequests(t *testing.T) {
	h := newHarness(t, scopesJSON)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := h.request("POST", create, composeBody(t)); r.code != 201 {
				t.Error(r)
			}
			h.request("POST", "/containers/valheim/exec", map[string]any{"Cmd": []any{"x"}})
		}()
	}
	wg.Wait()
}
