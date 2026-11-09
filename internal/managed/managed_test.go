package managed

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/dockerguard"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/modules"
)

const policy = `
games_root: /srv/games
names: ["gs-*", minecraft]
images: ["docker.io/itzg/*", lloesche/valheim-server]
networks: [crowsnest-games-net]
ports: ["25000-26000/tcp", "27000-27999/udp"]
host_ips: [10.0.0.2]
exec: true
`

type fakeDocker struct {
	mu      sync.Mutex
	created []dockerctl.CreateSpec
	pulled  []string
	have    map[string]bool
	running map[string]bool
}

func (f *fakeDocker) Create(_ context.Context, s dockerctl.CreateSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, s)
	f.have[s.Name] = true
	return nil
}
func (f *fakeDocker) Pull(_ context.Context, i string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pulled = append(f.pulled, i)
	return nil
}
func (f *fakeDocker) Remove(_ context.Context, n string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.have, n)
	return nil
}
func (f *fakeDocker) Exists(_ context.Context, n string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.have[n], nil
}
func (f *fakeDocker) Running(_ context.Context, n string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running[n], nil
}

func newManager(t *testing.T) (*Manager, *fakeDocker) {
	t.Helper()
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, _ := games.NewRegistry(nil)
	fd := &fakeDocker{have: map[string]bool{}, running: map[string]bool{}}
	m := &Manager{
		Dir: filepath.Join(dir, "managed"), PolicyFile: pol,
		Platform: modules.Platform{GamesRoot: "/srv/games", HostIP: "10.0.0.2"},
		Modules:  modules.Bundled(), Config: &config.Config{Games: []config.GameConfig{{ID: "windrose", ContainerName: "windrose"}}},
		Docker: fd, Wire: &dockerctl.Client{}, Registry: reg, Settle: time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := m.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	return m, fd
}

func waitState(t *testing.T, m *Manager, id, want string) {
	t.Helper()
	for i := 0; i < 300; i++ {
		for _, in := range m.List() {
			if in.ID == id && in.State == want {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never reached %s: %+v", id, want, m.List())
}

func TestEnableAndDisable(t *testing.T) {
	m, fd := newManager(t)
	req := Request{ID: "minecraft", Module: "minecraft",
		Options: map[string]string{"eula": "TRUE", "motd": "hi"}, Secrets: map[string]string{"rcon_password": "hunter2"}}
	plan, err := m.Preview(req)
	if err != nil || !plan.Fits || strings.Contains(plan.Service, "hunter2") || strings.Contains(plan.Scope, "hunter2") {
		t.Fatalf("preview: %+v %v", plan, err)
	}
	if err := m.Enable(req); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)

	if len(fd.created) != 1 || fd.pulled[0] != "itzg/minecraft-server:latest" {
		t.Fatalf("created=%+v pulled=%v", fd.created, fd.pulled)
	}
	env := strings.Join(fd.created[0].Env, "|")
	if !strings.Contains(env, "RCON_PASSWORD=hunter2") || !strings.Contains(env, "EULA=TRUE") || !strings.Contains(env, "MOTD=hi") {
		t.Errorf("env not resolved: %s", env)
	}
	if fd.created[0].Binds[0] != "/srv/games/Minecraft:/data" {
		t.Errorf("binds = %v", fd.created[0].Binds)
	}
	if _, ok := m.Registry.Get("minecraft"); !ok {
		t.Error("game not on the dashboard")
	}

	scopes, err := os.ReadFile(filepath.Join(m.Dir, "scopes.json"))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := dockerguard.LoadScopes(string(scopes))
	if err != nil || len(sc) != 1 {
		t.Fatalf("scopes.json: %v\n%s", err, scopes)
	}
	pol, _ := dockerguard.LoadPolicy(m.PolicyFile)
	if err := pol.Admit(sc[0]); err != nil {
		t.Errorf("written scope outside the policy: %v", err)
	}
	games, _ := os.ReadFile(filepath.Join(m.Dir, "games.json"))
	if strings.Contains(string(games), "hunter2") || strings.Contains(string(scopes), "hunter2") {
		t.Error("a secret leaked into a shared file")
	}
	if fi, _ := os.Stat(filepath.Join(m.Dir, "secrets.json")); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("secrets.json mode = %v", fi)
	}

	// survives a restart
	m2, _ := newManagerAt(t, m)
	if _, ok := m2.Registry.Get("minecraft"); !ok {
		t.Error("game not restored after restart")
	}

	fd.running["minecraft"] = true
	if err := m.Disable("minecraft"); err == nil {
		t.Error("a running game was disabled")
	}
	fd.running["minecraft"] = false
	if err := m.Disable("minecraft"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Registry.Get("minecraft"); ok || fd.have["minecraft"] {
		t.Error("game or container left behind")
	}
	if b, _ := os.ReadFile(filepath.Join(m.Dir, "scopes.json")); strings.TrimSpace(string(b)) != "[]" {
		t.Errorf("scopes.json after disable: %s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(m.Dir, "secrets.json")); strings.Contains(string(b), "hunter2") {
		t.Error("secret kept after disable")
	}
}

func newManagerAt(t *testing.T, old *Manager) (*Manager, *fakeDocker) {
	t.Helper()
	reg, _ := games.NewRegistry(nil)
	fd := &fakeDocker{have: map[string]bool{"minecraft": true}, running: map[string]bool{}}
	m := &Manager{Dir: old.Dir, PolicyFile: old.PolicyFile, Platform: old.Platform, Modules: old.Modules, Config: old.Config,
		Docker: fd, Wire: &dockerctl.Client{}, Registry: reg, Settle: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := m.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	return m, fd
}

func TestEnableRefusals(t *testing.T) {
	m, fd := newManager(t)
	cases := map[string]Request{
		"bad id":           {ID: "Bad_ID", Module: "minecraft", Secrets: map[string]string{"rcon_password": "x"}, Options: map[string]string{"eula": "TRUE"}},
		"unknown module":   {ID: "nope", Module: "nope"},
		"taken by config":  {ID: "windrose", Module: "minecraft"},
		"secret as option": {ID: "minecraft", Module: "minecraft", Options: map[string]string{"rcon_password": "x"}},
		"unknown option":   {ID: "minecraft", Module: "minecraft", Options: map[string]string{"privileged": "true"}},
		"newline":          {ID: "minecraft", Module: "minecraft", Options: map[string]string{"motd": "a\nb"}},
		"needs image":      {ID: "gs-tf2", Module: "source", Options: map[string]string{"rcon_addr": "gs-tf2:27015"}, Secrets: map[string]string{}},
		"port outside":     {ID: "minecraft", Module: "minecraft", Options: map[string]string{"ports": "22:25565/tcp"}},
		"image outside":    {ID: "minecraft", Module: "minecraft", Options: map[string]string{"image": "evil/miner"}},
		"name outside":     {ID: "caddy", Module: "minecraft", Options: map[string]string{}},
		"path escape":      {ID: "minecraft", Module: "minecraft", Options: map[string]string{"data_dir": "../etc"}},
	}
	for name, req := range cases {
		if err := m.Enable(req); err == nil {
			t.Errorf("%s: was accepted", name)
		}
	}
	if len(fd.created) != 0 || len(m.List()) != 0 {
		t.Errorf("a refused request left state behind: %+v %+v", fd.created, m.List())
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "scopes.json")); err == nil {
		t.Error("a refused request wrote scopes")
	}
	// the plan says why when it does not fit
	p, err := m.Preview(Request{ID: "minecraft", Module: "minecraft", Options: map[string]string{"ports": "22:25565/tcp"}, Secrets: map[string]string{"rcon_password": "x"}})
	if err != nil || p.Fits || !strings.Contains(p.Reason, "port") {
		t.Errorf("plan: %+v %v", p, err)
	}
}

// The created container is exactly what the real guard lets through, and a
// request before the guard has the scope is the retriable 403.
func TestCreateThroughRealGuard(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "engine.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var hits []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/containers/create" {
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"Id":"abc","Warnings":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"done"}` + "\n"))
	})}
	go srv.Serve(l)
	defer srv.Close()

	m, _ := newManager(t)
	m.Docker = nil
	g, mf, err := m.validate(Request{ID: "minecraft", Module: "minecraft", Options: map[string]string{"eula": "TRUE"}, Secrets: map[string]string{"rcon_password": "x"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	rd, err := m.renderAndFit(g, mf)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := rd.Spec(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	js, _ := modules.ScopesJSON([]*modules.Rendered{rd})
	scopes, err := dockerguard.LoadScopes(string(js))
	if err != nil {
		t.Fatal(err)
	}

	guard := dockerguard.New(sock, scopes)
	gl, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go guard.ServeContext(ctx, gl)
	client := &dockerctl.Client{Host: "tcp://" + gl.Addr().String()}

	if err := client.Pull(ctx, spec.Image); err != nil {
		t.Fatalf("pull through the guard: %v", err)
	}
	if err := client.Create(ctx, spec); err != nil {
		t.Fatalf("create through the guard: %v", err)
	}

	// a spec the policy would never render is refused by the guard
	bad := spec
	bad.Ports = []dockerctl.PortBinding{{HostIP: "0.0.0.0", HostPort: 22, ContainerPort: 25565, Proto: "tcp"}}
	if err := client.Create(ctx, bad); !dockerctl.IsDenied(err) {
		t.Errorf("create with a foreign port: want a denial, got %v", err)
	}
	bad = spec
	bad.Binds = []string{"/etc:/data"}
	if err := client.Create(ctx, bad); !dockerctl.IsDenied(err) {
		t.Errorf("create with a foreign bind: want a denial, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hits) != 2 {
		t.Errorf("engine saw %v, want only the pull and the one good create", hits)
	}
}
