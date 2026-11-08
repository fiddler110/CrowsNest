package dockerguard

// The guard against a fake Docker engine on a unix socket. Each refused
// request is checked twice: the client gets a refusal, and the fake engine
// never saw it.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	palDir     = "/home/plex/docker/storage/mounts/Palworld"
	palImageID = "sha256:f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6"
	digest     = "sha256:1717171717171717171717171717171717171717171717171717171717171717"
	execID     = "9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e"
)

var (
	palID      = strings.Repeat("a1", 32)
	vwID       = strings.Repeat("b2", 32)
	valID      = strings.Repeat("c3", 32)
	netID      = strings.Repeat("d4", 32)
	otherNetID = strings.Repeat("e5", 32)
	retiredID  = strings.Repeat("ab", 32)
)

const scopesJSON = `[{
  "name": "palworld",
  "images": ["thijsvanloef/palworld-server-docker"],
  "binds": ["` + palDir + `"],
  "networks": ["crowsnest-games-net"],
  "ports": [{"host_ip": "10.0.0.2", "host_port": "8211", "proto": "udp"}],
  "labels": {"com.centurylinklabs.watchtower.enable": "false"}
}, {
  "name": "valheim",
  "images": ["lloesche/valheim-server"],
  "binds": ["/srv/valheim", "/srv/valheim/backups"],
  "aliases": ["valheim-server"],
  "volumes": ["crowsnest-games_"],
  "networks": ["crowsnest-games-net"],
  "exec": true
}]`

// jv decodes JSON text, with the placeholders PALDIR, NETID, OTHERNETID, PALIMG and DIGEST filled in.
func jv(t testing.TB, text string) map[string]any {
	t.Helper()
	text = strings.NewReplacer("PALDIR", palDir, "OTHERNETID", otherNetID, "NETID", netID, "PALIMG", palImageID, "DIGEST", digest).Replace(text)
	var v map[string]any
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("bad test JSON %s: %v", text, err)
	}
	return v
}

func labels(service string) map[string]any {
	return map[string]any{"com.docker.compose.project": "crowsnest-games", "com.docker.compose.service": service,
		"com.docker.compose.oneoff": "False", "com.docker.compose.container-number": "1"}
}

var (
	containers = func() []any {
		return []any{
			map[string]any{"Id": palID, "Names": []any{"/palworld"}, "Image": "thijsvanloef/palworld-server-docker:latest", "Labels": labels("palworld"), "State": "running"},
			map[string]any{"Id": valID, "Names": []any{"/valheim"}, "Image": "lloesche/valheim-server", "Labels": labels("valheim"), "State": "exited"},
			map[string]any{"Id": vwID, "Names": []any{"/vaultwarden"}, "Image": "vaultwarden/server:latest",
				"Labels": map[string]any{"com.docker.compose.project": "vaultwarden", "secret.hint": "admin-token-here"}, "State": "running"},
		}
	}()
	// compose's replacement for valheim, made under the temporary name while the current valheim (valID) still stands;
	// inspectable but in no list
	recreated = map[string]any{"Id": strings.Repeat("f6", 32), "Names": []any{"/" + valID[:12] + "_valheim"}, "Image": "lloesche/valheim-server", "Labels": labels("valheim"), "State": "created"}
	retired   = map[string]any{"Id": retiredID, "Names": []any{"/" + retiredID[:12] + "_valheim"}, "Image": "lloesche/valheim-server", "Labels": labels("valheim"), "State": "exited"}
	images    = []any{
		map[string]any{"Id": palImageID, "RepoTags": []any{"thijsvanloef/palworld-server-docker:latest"},
			"RepoDigests": []any{"thijsvanloef/palworld-server-docker@" + digest}},
		map[string]any{"Id": "sha256:" + strings.Repeat("01", 32), "RepoTags": []any{"evil.example.com/thijsvanloef/palworld-server-docker:latest"}, "RepoDigests": []any{}},
		map[string]any{"Id": "sha256:" + strings.Repeat("02", 32), "RepoTags": []any{"vaultwarden/server:latest"}, "RepoDigests": []any{}},
	}
	networks = []any{
		map[string]any{"Name": "crowsnest-games-net", "Id": netID, "Driver": "bridge", "Labels": map[string]any{"com.docker.compose.project": "crowsnest"},
			"Containers": map[string]any{palID: map[string]any{"Name": "palworld", "IPv4Address": "172.30.0.2/16"}, vwID: map[string]any{"Name": "vaultwarden", "IPv4Address": "172.30.0.3/16"}}},
		map[string]any{"Name": "vaultwarden_default", "Id": otherNetID, "Driver": "bridge", "Containers": map[string]any{}},
		map[string]any{"Name": "bridge", "Id": strings.Repeat("f0", 32), "Driver": "bridge", "Containers": map[string]any{}},
	}
	volumes = map[string]any{"Volumes": []any{map[string]any{"Name": "crowsnest-games_saves", "Driver": "local"}, map[string]any{"Name": "immich_pgdata", "Driver": "local"}}, "Warnings": nil}
	info    = map[string]any{"ID": "HOST-ID", "Name": "my-secret-hostname", "ServerVersion": "29.0.1", "OSType": "linux", "Architecture": "x86_64",
		"KernelVersion": "7.0.0-42-generic", "Driver": "overlay2", "DriverStatus": []any{[]any{"Backing Filesystem", "extfs"}},
		"CgroupDriver": "systemd", "CgroupVersion": "2", "DefaultRuntime": "runc", "LoggingDriver": "json-file",
		"SecurityOptions": []any{"name=apparmor", "name=seccomp,profile=builtin"}, "IndexServerAddress": "https://index.docker.io/v1/",
		"Containers": 47, "Images": 120, "DockerRootDir": "/var/lib/docker", "HttpProxy": "http://user:pw@proxy:3128",
		"Labels": []any{"owner=plex"}, "RegistryConfig": map[string]any{"Mirrors": []any{"https://mirror.internal"}}, "NCPU": 8, "MemTotal": 15 * (1 << 30),
		"Swarm": map[string]any{"LocalNodeState": "active", "NodeID": "node-secret"}, "Warnings": []any{"WARNING: something about the host"}}
)

func findContainer(ref string) map[string]any {
	for _, c := range append(append([]any{}, containers...), retired, recreated) {
		cm := c.(map[string]any)
		name := cm["Names"].([]any)[0].(string)
		id := cm["Id"].(string)
		if ref == id || ref == name[1:] || (len(ref) >= 3 && strings.HasPrefix(id, ref)) {
			state := cm["State"].(string)
			return map[string]any{"Id": id, "Name": name,
				"Config":     map[string]any{"Image": cm["Image"], "Labels": cm["Labels"], "Env": []any{"SECRET=1"}},
				"HostConfig": map[string]any{}, "State": map[string]any{"Status": state, "Running": state == "running"}}
		}
	}
	return nil
}

func findImage(ref string) map[string]any {
	for _, img := range images {
		im := img.(map[string]any)
		var tags []string
		for _, k := range []string{"RepoTags", "RepoDigests"} {
			for _, x := range im[k].([]any) {
				tags = append(tags, x.(string))
			}
		}
		if ref == im["Id"] {
			return im
		}
		for _, tg := range tags {
			if ref == tg || ref+":latest" == tg || strings.TrimPrefix(ref, "docker.io/") == tg {
				return im
			}
		}
	}
	return nil
}

// seenReq is one request the fake engine received.
type seenReq struct {
	method, path string
	q            url.Values
	body         []byte
	header       http.Header
	uri          string
}

type fakeEngine struct {
	mu   sync.Mutex
	seen []seenReq
}

func (e *fakeEngine) clear() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seen = nil
}

func (e *fakeEngine) reached(method, path string) []seenReq {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []seenReq
	for _, s := range e.seen {
		if s.method == method && s.path == path {
			out = append(out, s)
		}
	}
	return out
}

func (e *fakeEngine) all() []seenReq {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]seenReq(nil), e.seen...)
}

func writeJSON(w http.ResponseWriter, status int, doc any) {
	data, _ := json.Marshal(doc)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	w.Header().Set("Api-Version", "1.52")
	w.WriteHeader(status)
	w.Write(data)
}

func (e *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	path := r.URL.Path
	if strings.HasPrefix(path, "/v1.") {
		path = "/" + strings.SplitN(path, "/", 3)[2]
	}
	q := r.URL.Query()
	e.mu.Lock()
	e.seen = append(e.seen, seenReq{r.Method, path, q, body, r.Header.Clone(), r.RequestURI})
	e.mu.Unlock()
	cmd := r.Method
	switch {
	case path == "/_ping":
		w.Header().Set("Api-Version", "1.52")
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(200)
		if cmd != "HEAD" {
			w.Write([]byte("OK"))
		}
		return
	case path == "/version":
		writeJSON(w, 200, map[string]any{"ApiVersion": "1.52", "Version": "29.0.1", "Os": "linux"})
		return
	case path == "/info":
		writeJSON(w, 200, info)
		return
	case path == "/containers/json":
		writeJSON(w, 200, containers)
		return
	case path == "/images/json":
		writeJSON(w, 200, images)
		return
	case path == "/networks":
		writeJSON(w, 200, networks)
		return
	case path == "/volumes":
		writeJSON(w, 200, volumes)
		return
	case strings.HasPrefix(path, "/networks/") && cmd == "GET":
		ref := strings.SplitN(path, "/", 3)[2]
		for _, n := range networks {
			nm := n.(map[string]any)
			if ref == nm["Name"] || ref == nm["Id"] || strings.HasPrefix(nm["Id"].(string), ref) {
				writeJSON(w, 200, nm)
				return
			}
		}
		writeJSON(w, 404, map[string]any{"message": "network not found"})
		return
	case strings.HasPrefix(path, "/volumes/") && cmd == "GET":
		for _, v := range volumes["Volumes"].([]any) {
			if v.(map[string]any)["Name"] == strings.SplitN(path, "/", 3)[2] {
				writeJSON(w, 200, v)
				return
			}
		}
		writeJSON(w, 404, map[string]any{"message": "no such volume"})
		return
	case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json") && cmd == "GET":
		if img := findImage(path[len("/images/") : len(path)-len("/json")]); img != nil {
			writeJSON(w, 200, img)
		} else {
			writeJSON(w, 404, map[string]any{"message": "No such image"})
		}
		return
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json") && cmd == "GET":
		if c := findContainer(strings.Split(path, "/")[2]); c != nil {
			writeJSON(w, 200, c)
		} else {
			writeJSON(w, 404, map[string]any{"message": "No such container"})
		}
		return
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/logs"):
		switch strings.ToLower(strings.TrimSpace(q.Get("follow"))) {
		case "", "0", "no", "false", "none":
		default: // Moby's BoolValue
			w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
			w.WriteHeader(200)
			fl := w.(http.Flusher)
			for i := 0; i < 20; i++ {
				if _, err := fmt.Fprintf(w, "log line %d\n", i); err != nil {
					return
				}
				fl.Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(50 * time.Millisecond):
				}
			}
			return
		}
		n := 1
		if q.Get("tail") == "all" {
			n = 5000
		}
		writeJSON(w, 200, strings.Repeat("log line\n", n))
		return
	case path == "/containers/create" && cmd == "POST":
		writeJSON(w, 201, map[string]any{"Id": "new" + strings.Repeat("0", 61), "Warnings": []any{}})
		return
	case strings.HasSuffix(path, "/exec") && cmd == "POST":
		writeJSON(w, 201, map[string]any{"Id": execID})
		return
	case strings.HasPrefix(path, "/exec/") && strings.HasSuffix(path, "/start"):
		var b struct{ Detach bool }
		_ = json.Unmarshal(body, &b)
		if b.Detach {
			writeJSON(w, 200, map[string]any{})
			return
		}
		if _, ok := r.Header["Upgrade"]; ok {
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			conn.Write([]byte("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"))
			p := make([]byte, 65536)
			for {
				n, err := buf.Read(p)
				if n > 0 {
					conn.Write(append([]byte("echo:"), p[:n]...))
				}
				if err != nil {
					return
				}
			}
		}
	case path == "/images/create":
		writeJSON(w, 200, map[string]any{"status": "Downloaded newer image"})
		return
	case cmd == "POST" && (strings.HasSuffix(path, "/start") || strings.HasSuffix(path, "/stop") || strings.HasSuffix(path, "/restart")):
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(204)
		return
	}
	writeJSON(w, 200, map[string]any{"fake": "default answer", "path": path})
}

// shortDir is a temp directory with a path short enough for a unix socket.
func shortDir(t testing.TB) string {
	t.Helper()
	d, err := os.MkdirTemp("", "gg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// harness is a guard on 127.0.0.1:<random> in front of the fake engine.
type harness struct {
	t    testing.TB
	g    *Guard
	eng  *fakeEngine
	addr string

	mu   sync.Mutex
	logs []string // the guard's DENY lines
}

func (h *harness) logged() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.logs, "\n")
}

func newHarness(t testing.TB, scopes string, tweak ...func(*Guard)) *harness {
	t.Helper()
	eng := &fakeEngine{}
	sock := shortDir(t) + "/d.sock"
	ul, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: eng}
	go srv.Serve(ul)
	t.Cleanup(func() { srv.Close() })

	sc, err := LoadScopes(scopes)
	if err != nil {
		t.Fatalf("scopes: %v", err)
	}
	g := New(sock, sc)
	g.streamIdle = 5 * time.Second
	for _, fn := range tweak {
		fn(g)
	}
	h := &harness{t: t, g: g, eng: eng}
	g.Logf = func(f string, a ...any) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.logs = append(h.logs, fmt.Sprintf(f, a...))
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.addr = l.Addr().String()
	return h.start(l)
}

func (h *harness) start(l net.Listener) *harness {
	go h.g.Serve(l)
	h.t.Cleanup(func() { l.Close() })
	return h
}

func (h *harness) reached(method, path string) []seenReq { return h.eng.reached(method, path) }

type result struct {
	code int
	raw  []byte
}

func (r result) json() any {
	var v any
	_ = json.Unmarshal(r.raw, &v)
	return v
}

func (r result) String() string { return fmt.Sprintf("%d %s", r.code, r.raw) }

// request makes one request on a fresh connection. body is JSON-encoded unless it is []byte or string.
func (h *harness) request(method, path string, body any, headers ...map[string]string) result {
	h.t.Helper()
	var data []byte
	switch b := body.(type) {
	case nil:
	case []byte:
		data = b
	case string:
		data = []byte(b)
	default:
		var err error
		if data, err = json.Marshal(b); err != nil {
			h.t.Fatal(err)
		}
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, "http://"+h.addr+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, hm := range headers {
		for k, v := range hm {
			req.Header.Set(k, v)
		}
	}
	cl := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 15 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return result{resp.StatusCode, raw}
}

// raw sends bytes (optionally more after a pause) and returns everything the guard sent back.
func (h *harness) raw(data []byte, wait time.Duration, then []byte, thenWait time.Duration) []byte {
	h.t.Helper()
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		h.t.Fatal(err)
	}
	defer c.Close()
	c.Write(data)
	out := drain(c, wait)
	if then != nil {
		c.Write(then)
		out = append(out, drain(c, thenWait)...)
	}
	return out
}

func drain(c net.Conn, d time.Duration) []byte {
	var out []byte
	end := time.Now().Add(d)
	buf := make([]byte, 65536)
	for time.Now().Before(end) {
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
	}
	return out
}

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

// refused asserts the guard answered with one of the refusal statuses.
func (h *harness) refused(method, path string, body any, headers ...map[string]string) result {
	h.t.Helper()
	r := h.request(method, path, body, headers...)
	switch r.code {
	case 400, 403, 404, 405:
	default:
		h.t.Fatalf("%s %s: want a refusal, got %s", method, path, r)
	}
	return r
}

// post renders a raw POST request for h.raw.
func post(path string, body any) []byte {
	b, _ := json.Marshal(body)
	return append([]byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", path, len(b))), b...)
}

var evilCreate = post("/containers/create?name=palworld", map[string]any{"Image": "alpine", "HostConfig": map[string]any{"Privileged": true, "Binds": []any{"/:/host"}}})

const composeJSON = `{
  "Hostname": "", "Domainname": "", "User": "", "AttachStdin": false, "AttachStdout": false, "AttachStderr": false,
  "ExposedPorts": {"8211/udp": {}}, "Tty": false, "OpenStdin": false, "StdinOnce": false,
  "Env": ["TZ=Europe/Amsterdam", "PUID=1000", "PGID=1000", "PORT=8211", "PLAYERS=8", "SERVER_NAME=CrowsNest Palworld",
          "COMMUNITY=false", "REST_API_ENABLED=true", "REST_API_PORT=8212", "ADMIN_PASSWORD=hunter2"],
  "Cmd": null, "Image": "thijsvanloef/palworld-server-docker:latest", "Volumes": null, "WorkingDir": "", "Entrypoint": null,
  "OnBuild": null, "StopTimeout": 60,
  "Labels": {"com.docker.compose.project": "crowsnest-games", "com.docker.compose.service": "palworld",
             "com.docker.compose.oneoff": "False", "com.docker.compose.container-number": "1",
             "com.docker.compose.config-hash": "9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f",
             "com.docker.compose.depends_on": "", "com.docker.compose.image": "PALIMG",
             "com.docker.compose.project.config_files": "/data/compose.yaml", "com.docker.compose.project.working_dir": "/data",
             "com.docker.compose.version": "5.7.0", "com.centurylinklabs.watchtower.enable": "false"},
  "HostConfig": {
    "Binds": ["PALDIR:/palworld:rw"], "ContainerIDFile": "",
    "LogConfig": {"Type": "json-file", "Config": {"max-file": "3", "max-size": "10m"}},
    "NetworkMode": "crowsnest-games-net",
    "PortBindings": {"8211/udp": [{"HostIp": "10.0.0.2", "HostPort": "8211"}]},
    "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0}, "AutoRemove": false, "VolumeDriver": "",
    "VolumesFrom": null, "ConsoleSize": [0, 0], "CapAdd": null, "CapDrop": null, "CgroupnsMode": "", "Dns": [],
    "DnsOptions": [], "DnsSearch": [], "ExtraHosts": ["host.docker.internal:host-gateway"], "GroupAdd": null, "IpcMode": "",
    "Cgroup": "", "Links": null, "OomScoreAdj": 0, "PidMode": "", "Privileged": false, "PublishAllPorts": false,
    "ReadonlyRootfs": false, "SecurityOpt": ["no-new-privileges:true"], "UTSMode": "", "UsernsMode": "", "ShmSize": 0,
    "Isolation": "", "CpuShares": 0, "Memory": 10737418240, "NanoCpus": 0, "CgroupParent": "", "BlkioWeight": 0,
    "BlkioWeightDevice": null, "BlkioDeviceReadBps": null, "BlkioDeviceWriteBps": null, "BlkioDeviceReadIOps": null,
    "BlkioDeviceWriteIOps": null, "CpuPeriod": 0, "CpuQuota": 0, "CpuRealtimePeriod": 0, "CpuRealtimeRuntime": 0,
    "CpusetCpus": "", "CpusetMems": "", "Devices": null, "DeviceCgroupRules": null, "DeviceRequests": null,
    "MemoryReservation": 0, "MemorySwap": 0, "MemorySwappiness": null, "OomKillDisable": false, "PidsLimit": null,
    "Ulimits": null, "CpuCount": 0, "CpuPercent": 0, "IOMaximumIOps": 0, "IOMaximumBandwidth": 0,
    "MaskedPaths": null, "ReadonlyPaths": null, "Init": null
  },
  "NetworkingConfig": {"EndpointsConfig": {"crowsnest-games-net": {
    "IPAMConfig": {"IPv4Address": "", "IPv6Address": "", "LinkLocalIPs": null}, "Links": null,
    "Aliases": ["palworld", "palworld"], "DriverOpts": null, "GwPriority": 0, "MacAddress": "", "NetworkID": "",
    "EndpointID": "", "Gateway": "", "IPAddress": "", "IPPrefixLen": 0, "IPv6Gateway": "", "GlobalIPv6Address": "",
    "GlobalIPv6PrefixLen": 0, "DNSNames": null}}}
}`

// composeBody is what docker compose v5 sends for the palworld service (Go
// marshals every field, most of them zero). hostJSON, if given, is a JSON object
// merged over HostConfig, as Python's dict.update did.
func composeBody(t testing.TB, hostJSON ...string) map[string]any {
	t.Helper()
	body := jv(t, composeJSON)
	host := body["HostConfig"].(map[string]any)
	for _, h := range hostJSON {
		for k, v := range jv(t, h) {
			host[k] = v
		}
	}
	return body
}
