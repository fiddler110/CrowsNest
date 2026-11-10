package managed

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
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
images: ["docker.io/itzg/*", lloesche/valheim-server, thijsvanloef/palworld-server-docker]
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
	if fd.created[0].Binds[0] != "/srv/games/Minecraft-minecraft:/data" {
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

func TestUpdateAndRefresh(t *testing.T) {
	m, fd := newManager(t)
	req := Request{ID: "minecraft", Module: "minecraft",
		Options: map[string]string{"eula": "TRUE", "motd": "one"}, Secrets: map[string]string{"rcon_password": "hunter2"}}
	if err := m.Enable(req); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	if v, ok := os.LookupEnv("MINECRAFT_RCON_PASSWORD"); ok && v == "hunter2" {
		t.Error("the secret was put into the process environment")
	}

	// settings change: container recreated with the new value, the stored secret kept
	fd.running["minecraft"] = true
	if err := m.Update(Request{ID: "minecraft", Options: map[string]string{"eula": "TRUE", "motd": "two"}}); err == nil {
		t.Error("a running game was changed")
	}
	fd.running["minecraft"] = false
	if err := m.Update(Request{ID: "minecraft", Module: "valheim"}); err == nil {
		t.Error("the module was changed")
	}
	if err := m.Update(Request{ID: "minecraft", Options: map[string]string{"eula": "TRUE", "motd": "two", "ports": "22:25565/tcp"}}); err == nil {
		t.Error("an update outside the policy was accepted")
	}
	if err := m.Update(Request{ID: "minecraft", Options: map[string]string{"eula": "TRUE", "motd": "two"}}); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	fd.mu.Lock()
	last := fd.created[len(fd.created)-1]
	n := len(fd.created)
	fd.mu.Unlock()
	env := strings.Join(last.Env, "|")
	if n != 2 || !strings.Contains(env, "MOTD=two") || !strings.Contains(env, "RCON_PASSWORD=hunter2") {
		t.Errorf("update: %d creates, env %s", n, env)
	}
	if _, ok := m.Registry.Get("minecraft"); !ok {
		t.Error("game missing from the dashboard after an update")
	}

	// refresh: pulls again and recreates, same settings
	pulls := len(fd.pulled)
	if err := m.Refresh("minecraft"); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if len(fd.pulled) != pulls+1 || len(fd.created) != 3 || !strings.Contains(strings.Join(fd.created[2].Env, "|"), "MOTD=two") {
		t.Errorf("refresh: pulls %d->%d, creates %d", pulls, len(fd.pulled), len(fd.created))
	}
}

// The exec allowlist for dashboard games comes from the module, so what the
// panel writes into games.json can pick a game but never a command.
func TestExecRulesComeFromModules(t *testing.T) {
	m, _ := newManager(t)
	if err := m.Enable(Request{ID: "minecraft", Module: "minecraft", Options: map[string]string{"eula": "TRUE"},
		Secrets: map[string]string{"rcon_password": "x"}}); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	rules, err := ExecRules(m.Dir, m.Modules)
	if err != nil || len(rules) != 2 || rules[0].Container != "minecraft" || rules[0].Cmd[0] != "/bin/sh" {
		t.Fatalf("rules = %+v, %v", rules, err)
	}
	if !strings.Contains(strings.Join(rules[1].Cmd, " "), "/data/backups") {
		t.Errorf("listing rule = %v", rules[1].Cmd)
	}
	// a hand-edited state file: a command in it is not read, an unknown module or odd id is ignored
	tampered := `{"games":[{"id":"minecraft","module":"minecraft","backup":{"exec":["rm","-rf","/"]}},
	  {"id":"caddy","module":"nope"},{"id":"../x","module":"minecraft"}]}`
	if err := os.WriteFile(filepath.Join(m.Dir, "games.json"), []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, _ = ExecRules(m.Dir, m.Modules)
	for _, r := range rules {
		if r.Container != "minecraft" || r.Cmd[0] == "rm" {
			t.Errorf("unexpected rule %+v", r)
		}
	}
	if len(rules) != 2 {
		t.Errorf("rules = %+v", rules)
	}
}

func TestListCarriesEditFieldsButNoSecrets(t *testing.T) {
	m, _ := newManager(t)
	req := Request{ID: "minecraft", Module: "minecraft", DisplayName: "Minecraft", ConnectAddress: "10.0.0.2:25565",
		Options: map[string]string{"eula": "TRUE", "motd": "hi"}, Secrets: map[string]string{"rcon_password": "hunter2"}}
	if err := m.Enable(req); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	got := m.List()[0]
	if got.DisplayName != "Minecraft" || got.ConnectAddress != "10.0.0.2:25565" || got.Options["motd"] != "hi" {
		t.Errorf("edit fields missing: %+v", got)
	}
	if b, _ := json.Marshal(got); strings.Contains(string(b), "hunter2") {
		t.Errorf("a secret leaked into the list: %s", b)
	}
}

func TestCatalogueDescribesAndProbesFit(t *testing.T) {
	m, _ := newManager(t)
	var mc *ModuleInfo
	for _, mi := range m.Catalogue() {
		if mi.ID == "minecraft" {
			c := mi
			mc = &c
		}
	}
	if mc == nil {
		t.Fatal("minecraft missing from the catalogue")
	}
	if mc.Description == "" || mc.Image == "" || len(mc.Ports) == 0 || !mc.HasBackup {
		t.Errorf("catalogue entry is thin: %+v", mc)
	}
	if mc.Fits == nil || !*mc.Fits {
		t.Errorf("minecraft should fit the test policy: %+v", mc)
	}
}

func TestDerivedOptionsFillThemselvesIn(t *testing.T) {
	if got := deriveOption("http://{id}:8212", "pal-1"); got != "http://pal-1:8212" {
		t.Errorf("derive {id} = %q", got)
	}
	if got := deriveOption("{env:admin_password}", "pal-1"); got != envName("pal-1", "admin_password") {
		t.Errorf("derive {env:} = %q", got)
	}
	m, _ := newManager(t)
	// Palworld asks for an admin password only: the API address and the variable holding it follow from the game.
	g, mf, err := m.validate(Request{ID: "pal-1", Module: "palworld", Secrets: map[string]string{"admin_password": "pw"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if g.Options["rest_api_url"] != "http://pal-1:8212" || g.Options["rest_api_password_env"] != envName("pal-1", "admin_password") {
		t.Errorf("not derived: %v", g.Options)
	}
	if _, _, err := m.validate(Request{ID: "pal-2", Module: "palworld"}, false); err == nil {
		t.Error("a Palworld game without an admin password must be refused")
	}
	for _, o := range mf.Options {
		if o.Key == "rest_api_url" && o.Derive == "" {
			t.Error("rest_api_url lost its derive")
		}
	}
}

func TestPolicyEditing(t *testing.T) {
	m, _ := newManager(t)
	st, err := m.Policy()
	if err != nil || st.Editable || len(st.Policy.Names) == 0 {
		t.Fatalf("policy view: %+v %v", st, err)
	}
	if err := m.SetPolicy(st.Policy); err == nil {
		t.Fatal("a read-only policy was rewritten")
	}
	m.PolicyEditable = true
	st.Policy.Names = append(st.Policy.Names, "pal-*")
	if err := m.SetPolicy(st.Policy); err != nil {
		t.Fatal(err)
	}
	if again, _ := m.Policy(); !slices.Contains(again.Policy.Names, "pal-*") {
		t.Errorf("edit not saved: %+v", again.Policy)
	}
	bad := st.Policy
	bad.Names = []string{"*"}
	if err := m.SetPolicy(bad); err == nil {
		t.Error(`names: ["*"] was accepted`)
	}
	empty := st.Policy
	empty.Ports = nil
	if err := m.SetPolicy(empty); err == nil {
		t.Error("an empty ports list was accepted")
	}
	if kept, _ := m.Policy(); !slices.Contains(kept.Policy.Names, "pal-*") || len(kept.Policy.Ports) == 0 {
		t.Errorf("a refused edit changed the file: %+v", kept.Policy)
	}
}

func TestTwoGamesFromOneModule(t *testing.T) {
	m, fd := newManager(t)
	a := Request{ID: "gs-one", Module: "minecraft", Options: map[string]string{"eula": "TRUE"}, Secrets: map[string]string{"rcon_password": "x"}}
	if err := m.Enable(a); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "gs-one", StateReady)
	// Same module, default ports: refused, naming the game that holds the port.
	b := Request{ID: "gs-two", Module: "minecraft", Options: map[string]string{"eula": "TRUE"}, Secrets: map[string]string{"rcon_password": "y"}}
	if _, err := m.Preview(b); err == nil || !strings.Contains(err.Error(), "gs-one") {
		t.Fatalf("a shared host port was accepted: %v", err)
	}
	b.Options["ports"] = "25570:25565/tcp"
	if err := m.Enable(b); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "gs-two", StateReady)
	var binds []string
	for _, c := range fd.created {
		binds = append(binds, c.Binds...)
	}
	if len(binds) != 2 || binds[0] == binds[1] {
		t.Errorf("two games share a data folder: %v", binds)
	}
}

func TestJoinPasswordShownOnTheCard(t *testing.T) {
	m, _ := newManager(t)
	req := Request{ID: "gs-pal", Module: "palworld", Options: map[string]string{"ports": "27015:8211/udp"},
		Secrets: map[string]string{"admin_password": "adm", "server_password": "letmein"}}
	if err := m.Enable(req); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "gs-pal", StateReady)
	def, _ := m.Registry.Get("gs-pal")
	if len(def.ConnectSecrets) != 1 || def.ConnectSecrets[0].Label != "Join password" || def.ConnectSecrets[0].Value != "letmein" {
		t.Errorf("connect secrets = %+v", def.ConnectSecrets)
	}
	for _, g := range m.List() {
		if b, _ := json.Marshal(g); strings.Contains(string(b), "letmein") {
			t.Errorf("the join password leaked into the list: %s", b)
		}
	}
}
