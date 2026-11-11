package managed

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/fiddler110/crowsnest/internal/backup"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/dockerguard"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/modules"
	"github.com/fiddler110/crowsnest/internal/probes"
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
	digests map[string]string // repo:tag -> what it resolves to now (default: one per ref)
	removed []string
}

func defaultDigest(ref string) string {
	return "sha256:" + strings.Repeat(fmt.Sprintf("%02x", len(ref)), 32)
}

// ImageDigests answers as the engine does: a tag's image carries repo@digest; a digest ref is there or not.
func (f *fakeDocker) ImageDigests(_ context.Context, ref string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, _, byDigest := strings.Cut(ref, "@"); byDigest {
		return []string{ref}, nil
	}
	d := f.digests[ref]
	if d == "" {
		d = defaultDigest(ref)
	}
	repo := ref[:strings.LastIndex(ref, ":")]
	return []string{"other/mirror@sha256:" + strings.Repeat("0", 64), repo + "@" + d}, nil
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
	f.removed = append(f.removed, n)
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
	fd := &fakeDocker{have: map[string]bool{}, running: map[string]bool{}, digests: map[string]string{}}
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
	if fd.created[0].Binds[0] != "/srv/games/minecraft:/data" {
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
	// A start still pulling has no running container yet: the start/stop manager says it is busy.
	m.Busy = func(id string) bool { return id == "minecraft" }
	if err := m.Disable("minecraft"); err == nil || fd.have["minecraft"] == false {
		t.Errorf("disabled a game that is starting or stopping: err=%v", err)
	}
	if err := m.Update(Request{ID: "minecraft", Module: "minecraft", Options: map[string]string{"eula": "TRUE"}}); err == nil {
		t.Error("changed a game that is starting or stopping")
	}
	m.Busy = nil
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
	fd := &fakeDocker{have: map[string]bool{"minecraft": true}, running: map[string]bool{}, digests: map[string]string{}}
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

	// refresh: pulls again and, the tag now pointing at a new image, recreates with the same settings
	fd.mu.Lock()
	fd.digests["itzg/minecraft-server:latest"] = "sha256:" + strings.Repeat("2", 64)
	fd.mu.Unlock()
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
	rules, err := ExecRules(m.Dir, m.PolicyFile, m.Modules)
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
	rules, _ = ExecRules(m.Dir, m.PolicyFile, m.Modules)
	for _, r := range rules {
		if r.Container != "minecraft" || r.Cmd[0] == "rm" {
			t.Errorf("unexpected rule %+v", r)
		}
	}
	if len(rules) != 2 {
		t.Errorf("rules = %+v", rules)
	}
}

// A games.json entry named after a container the policy keeps out of the
// panel's reach gets no rule, even with a real module and a valid id.
func TestExecRulesStayInsideThePolicy(t *testing.T) {
	m, _ := newManager(t)
	tampered := `{"games":[{"id":"caddy","module":"minecraft"},{"id":"minecraft","module":"minecraft"}]}`
	if err := os.WriteFile(filepath.Join(m.Dir, "games.json"), []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := ExecRules(m.Dir, m.PolicyFile, m.Modules)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.Container == "caddy" {
			t.Errorf("rule for a container outside the policy: %+v", r)
		}
	}
	if len(rules) != 2 {
		t.Errorf("rules = %+v, want the minecraft pair only", rules)
	}
	if _, err := ExecRules(m.Dir, "", m.Modules); err == nil {
		t.Error("no policy file was accepted")
	}
	if _, err := ExecRules(m.Dir, filepath.Join(m.Dir, "missing.yaml"), m.Modules); err == nil {
		t.Error("an unreadable policy was accepted")
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
	wide := st.Policy
	wide.Names = append(slices.Clone(wide.Names), "pal-*")
	if err := m.SetPolicy(wide); err == nil {
		t.Fatal("the dashboard widened the policy")
	}
	narrow := st.Policy
	narrow.Names = st.Policy.Names[:1]
	if err := m.SetPolicy(narrow); err != nil {
		t.Fatal(err)
	}
	if again, _ := m.Policy(); len(again.Policy.Names) != 1 {
		t.Errorf("edit not saved: %+v", again.Policy)
	}
	bad := st.Policy
	bad.Names = []string{"*"}
	if err := m.SetPolicy(bad); err == nil {
		t.Error(`names: ["*"] was accepted`)
	}
	// an empty images or networks list means "the defaults", which would widen a listed policy
	for _, clear := range []func(*PolicyDoc){func(d *PolicyDoc) { d.Images = nil }, func(d *PolicyDoc) { d.Networks = nil }, func(d *PolicyDoc) { d.Names = nil }} {
		now, _ := m.Policy()
		cleared := now.Policy
		clear(&cleared)
		if err := m.SetPolicy(cleared); err == nil || !strings.Contains(err.Error(), "emptied") {
			t.Errorf("a list was emptied from the dashboard: %v", err)
		}
	}
	empty := st.Policy
	empty.Ports = nil
	if err := m.SetPolicy(empty); err == nil {
		t.Error("an empty ports list was accepted")
	}
	if kept, _ := m.Policy(); len(kept.Policy.Names) != 1 || len(kept.Policy.Ports) == 0 {
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
	// Same module, default ports: it moves to the next free host port by itself.
	b := Request{ID: "gs-two", Module: "minecraft", Options: map[string]string{"eula": "TRUE"}, Secrets: map[string]string{"rcon_password": "y"}}
	if p, err := m.Preview(b); err != nil || !strings.Contains(strings.Join(p.Ports, " "), "25566:25565") {
		t.Fatalf("the second game did not get its own port: %+v %v", p, err)
	}
	// A port typed by hand that is taken is refused, naming the game that holds it.
	b.Options["ports"] = "25565:25565/tcp"
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

const windrosePolicy = policy + `
exceptions:
  - name: windrose
    image: indifferentbroccoli/windrose-server-docker
    networks:
      dockervlan: [10.0.1.16]
      crowsnest-games-net: [192.168.0.50]
    secopts: [seccomp=unconfined]
`

var windroseReq = Request{ID: "windrose", Module: "windrose",
	Options: map[string]string{"lan_ipv4": "10.0.1.16", "games_ipv4": "192.168.0.50", "data_dir": "Windrose"},
	Secrets: map[string]string{"invite_code": "abc123", "server_password": "pw"}}

// Windrose fits only because the operator's policy names it, and what it gets is exactly that.
func TestWindroseNeedsAPolicyException(t *testing.T) {
	m, fd := newManager(t)
	m.Config = &config.Config{}
	plan, err := m.Preview(windroseReq)
	if err != nil || plan.Fits || !strings.Contains(plan.Reason, "windrose") {
		t.Fatalf("without an exception it must not fit, and say why: %+v %v", plan, err)
	}
	if err := m.Enable(windroseReq); err == nil {
		t.Fatal("enabled without an exception")
	}

	if err := os.WriteFile(m.PolicyFile, []byte(windrosePolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if plan, err = m.Preview(windroseReq); err != nil || !plan.Fits {
		t.Fatalf("with the exception it must fit: %+v %v", plan, err)
	}
	// other addresses are not covered
	other := windroseReq
	other.Options = map[string]string{"lan_ipv4": "10.0.1.99", "data_dir": "Windrose"}
	if plan, _ = m.Preview(other); plan.Fits || !strings.Contains(plan.Reason, "10.0.1.99") || !strings.Contains(plan.Reason, "10.0.1.16") {
		t.Fatalf("a different address must be refused and the allowed one named: %+v", plan)
	}
	if err := m.Enable(windroseReq); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "windrose", StateReady)
	spec := fd.created[0]
	if !slices.Contains(spec.SecOpts, "seccomp=unconfined") {
		t.Errorf("secopts = %v", spec.SecOpts)
	}
	got := map[string]string{}
	for _, n := range spec.Networks {
		got[n.Name] = n.IPv4
	}
	if got["dockervlan"] != "10.0.1.16" || got["crowsnest-games-net"] != "192.168.0.50" || len(got) != 2 {
		t.Errorf("networks = %+v", spec.Networks)
	}
	env := strings.Join(spec.Env, "|")
	if !strings.Contains(env, "INVITE_CODE=abc123") || !strings.Contains(env, "P2P_PROXY_ADDRESS=10.0.1.16") {
		t.Errorf("env = %s", env)
	}
	if spec.Binds[0] != "/srv/games/Windrose/Config:/home/steam/server-files" {
		t.Errorf("binds = %v", spec.Binds)
	}
	// a second Windrose cannot take the same LAN address
	dup := windroseReq
	dup.ID = "windrose2"
	dup.Options = map[string]string{"lan_ipv4": "10.0.1.16", "data_dir": "Windrose2"}
	if err := m.Enable(dup); err == nil || !strings.Contains(err.Error(), "10.0.1.16") || !strings.Contains(err.Error(), "windrose") {
		t.Errorf("same LAN address must be refused naming the holder: %v", err)
	}
}

// The dashboard shows exceptions and keeps them when it saves the rest of the policy, but cannot make one.
func TestPolicyExceptionsSurviveDashboardEdits(t *testing.T) {
	m, _ := newManager(t)
	if err := os.WriteFile(m.PolicyFile, []byte(windrosePolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	m.PolicyEditable = true
	st, _ := m.Policy()
	if len(st.Policy.Exceptions) != 1 {
		t.Fatalf("exception not shown: %+v", st.Policy)
	}
	st.Policy.Names = st.Policy.Names[:1]
	st.Policy.Exceptions = append(st.Policy.Exceptions, dockerguard.Exception{Name: "sneaky", Image: "evil/miner", SecOpts: []string{"seccomp=unconfined"}})
	if err := m.SetPolicy(st.Policy); err != nil {
		t.Fatal(err)
	}
	again, _ := m.Policy()
	if len(again.Policy.Exceptions) != 1 || again.Policy.Exceptions[0].Name != "windrose" || len(again.Policy.Names) != 1 {
		t.Errorf("after save: %+v", again.Policy)
	}
}

// The guard itself lets the excepted create through, and refuses the same spec for any other secopt.
func TestWindroseCreateThroughRealGuard(t *testing.T) {
	m, _ := newManager(t)
	m.Config = &config.Config{}
	if err := os.WriteFile(m.PolicyFile, []byte(windrosePolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	g, mf, err := m.validate(windroseReq, false)
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
		t.Fatalf("%v\n%s", err, js)
	}

	sock := filepath.Join(t.TempDir(), "engine.sock")
	l, _ := net.Listen("unix", sock)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	guard := dockerguard.New(sock, scopes)
	gl, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go guard.ServeContext(ctx, gl)
	client := &dockerctl.Client{Host: "tcp://" + gl.Addr().String()}

	if err := client.Create(ctx, spec); err != nil {
		t.Fatalf("the excepted create was refused by the guard: %v", err)
	}
	bad := spec
	bad.SecOpts = []string{"apparmor=unconfined"}
	if err := client.Create(ctx, bad); !dockerctl.IsDenied(err) {
		t.Errorf("another security option: want a denial, got %v", err)
	}
	bad = spec
	bad.Networks = []dockerctl.NetEndpoint{{Name: "dockervlan", IPv4: "10.0.1.77", GwPriority: 100}, {Name: "crowsnest-games-net"}}
	if err := client.Create(ctx, bad); !dockerctl.IsDenied(err) {
		t.Errorf("another address: want a denial, got %v", err)
	}
}

// The catalogue says why Windrose is not addable until the operator writes an exception, and flips once they do.
func TestCatalogueSaysWindroseNeedsAnException(t *testing.T) {
	m, _ := newManager(t)
	m.Config = &config.Config{} // no hand-written windrose to clash with
	find := func() ModuleInfo {
		for _, mi := range m.Catalogue() {
			if mi.ID == "windrose" {
				return mi
			}
		}
		t.Fatal("windrose is not in the catalogue")
		return ModuleInfo{}
	}
	mi := find()
	if !mi.NeedsException || mi.Fits == nil || *mi.Fits || !strings.Contains(mi.Reason, "exception") {
		t.Fatalf("without an exception: %+v", mi)
	}
	if err := os.WriteFile(m.PolicyFile, []byte(windrosePolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if mi = find(); mi.Fits == nil || !*mi.Fits {
		t.Fatalf("with the exception it should fit: %+v", mi)
	}
}

// Another game holding a module's default port must not blank the module's verdict in the catalogue.
func TestCatalogueVerdictIgnoresPortsInUse(t *testing.T) {
	m, _ := newManager(t)
	if err := m.Enable(Request{ID: "gs-one", Module: "minecraft", Options: map[string]string{"eula": "TRUE"}, Secrets: map[string]string{"rcon_password": "x"}}); err != nil {
		t.Fatal(err)
	}
	for _, mi := range m.Catalogue() {
		if mi.ID == "minecraft" && mi.Fits == nil {
			t.Fatalf("no verdict while gs-one holds minecraft's port: %+v", mi)
		}
	}
}

// The preview tells the operator exactly what to put in policy.yaml and what else to do on the host.
func TestWindrosePreviewGivesHostSteps(t *testing.T) {
	m, _ := newManager(t)
	m.Config = &config.Config{}
	plan, err := m.Preview(windroseReq)
	if err != nil || plan.Fits || len(plan.Setup) < 3 {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	first := plan.Setup[0]
	if first.Done == nil || *first.Done {
		t.Errorf("the policy step must be open while the policy has no exception: %+v", first)
	}
	for _, want := range []string{"exceptions:", "name: windrose", "dockervlan:", "10.0.1.16", "192.168.0.50", "seccomp=unconfined"} {
		if !strings.Contains(first.Command, want) {
			t.Errorf("generated exception lacks %q:\n%s", want, first.Command)
		}
	}
	// what it generated must be accepted by the policy parser and admit this very game
	pol, err := dockerguard.ParsePolicy([]byte(policy + "\n" + first.Command + "\n"))
	if err != nil {
		t.Fatalf("generated block does not parse: %v\n%s", err, first.Command)
	}
	g, mf, _ := m.validate(windroseReq, false)
	rd, _ := mf.Render(g, m.Platform)
	js, _ := modules.ScopesJSON([]*modules.Rendered{rd})
	sc, _ := dockerguard.LoadScopes(string(js))
	if err := pol.Admit(sc[0]); err != nil {
		t.Errorf("the generated exception does not admit the game it was made for: %v", err)
	}
	all := ""
	for _, s := range plan.Setup {
		all += s.Title + s.Detail + s.Command
	}
	if !strings.Contains(all, "{{range .IPAM.Config}}{{.Subnet}} {{end}}") {
		t.Errorf("a docker format string was mangled:\n%s", all)
	}
	if !strings.Contains(all, "iptables -I INPUT -s 10.0.1.16") || strings.Contains(all, "{lan_ipv4}") {
		t.Errorf("host steps not filled in:\n%s", all)
	}
	// once the policy has it, the first step reads as done
	if err := os.WriteFile(m.PolicyFile, []byte(windrosePolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if plan, _ = m.Preview(windroseReq); plan.Setup[0].Done == nil || !*plan.Setup[0].Done {
		t.Errorf("step not marked done: %+v", plan.Setup[0])
	}
}

// A game whose data folder lies inside another game's (or holds it) is refused
// up front: the guard would reject its scope, because a container that writes
// the outer folder can turn the inner one into a symlink to the host.
func TestDataFolderMayNotNestInAnotherGame(t *testing.T) {
	m, _ := newManager(t)
	a := Request{ID: "gs-one", Module: "minecraft", Options: map[string]string{"eula": "TRUE"}, Secrets: map[string]string{"rcon_password": "x"}}
	if err := m.Enable(a); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "gs-one", StateReady)
	for _, dir := range []string{"gs-one/x", "gs-one/x/y"} {
		b := Request{ID: "gs-two", Module: "minecraft", Options: map[string]string{"eula": "TRUE", "ports": "25570:25565/tcp", "data_dir": dir},
			Secrets: map[string]string{"rcon_password": "y"}}
		if err := m.Enable(b); err == nil || !strings.Contains(err.Error(), "inside") {
			t.Errorf("data_dir %s inside gs-one's folder: %v", dir, err)
		}
	}
	// the other way round: gs-one lives in /srv/games/gs-one, so a game in /srv/games is refused by the policy
	// already; one whose folder holds a deeper game is refused here
	c := Request{ID: "gs-three", Module: "minecraft", Options: map[string]string{"eula": "TRUE", "ports": "25571:25565/tcp", "data_dir": "deep/a"},
		Secrets: map[string]string{"rcon_password": "z"}}
	if err := m.Enable(c); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "gs-three", StateReady)
	d := Request{ID: "gs-four", Module: "minecraft", Options: map[string]string{"eula": "TRUE", "ports": "25572:25565/tcp", "data_dir": "deep"},
		Secrets: map[string]string{"rcon_password": "w"}}
	if _, err := m.Preview(d); err == nil || !strings.Contains(err.Error(), "inside") {
		t.Errorf("a folder holding gs-three's was accepted: %v", err)
	}
}

// A dashboard game reads only its own secrets: an option naming another
// variable of the panel's environment (rcon_password_env) must not make the
// panel send that variable's value (an OAuth client secret, a webhook URL)
// as the game's RCON password to an address the same form chose.
func TestGameCannotReadThePanelEnvironment(t *testing.T) {
	t.Setenv("CROWSNEST_TEST_PANEL_SECRET", "s3cret")
	m, _ := newManager(t)
	req := Request{ID: "gs-one", Module: "minecraft",
		Options: map[string]string{"eula": "TRUE", "rcon_addr": "attacker.example:25575", "rcon_password_env": "CROWSNEST_TEST_PANEL_SECRET"},
		Secrets: map[string]string{"rcon_password": "own"}}
	if err := m.Enable(req); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "gs-one", StateReady)
	def, ok := m.Registry.Get("gs-one")
	if !ok {
		t.Fatal("not registered")
	}
	rc, ok := def.RawConsole.(*probes.RawRCON)
	if !ok {
		t.Fatalf("raw console is %T", def.RawConsole)
	}
	if rc.Password == "s3cret" {
		t.Fatal("the game's RCON password was read from another variable of the panel's environment")
	}
	// its own variable still works
	lookup := m.lookup(m.find("gs-one"))
	if v, _ := lookup("GS_ONE_RCON_PASSWORD"); v != "own" {
		t.Errorf("own secret: %q", v)
	}
	if v, ok := lookup("CROWSNEST_TEST_PANEL_SECRET"); ok || v != "" {
		t.Errorf("container env lookup read the panel's environment: %q", v)
	}
}

// The dashboard may tighten the policy and never loosen it, whatever the
// field, so a compromised panel cannot widen its own limits.
func TestPolicyEditsNeverWiden(t *testing.T) {
	m, _ := newManager(t)
	m.PolicyEditable = true
	st, _ := m.Policy()
	base := st.Policy
	widen := map[string]func(d *PolicyDoc){
		"games_root": func(d *PolicyDoc) { d.GamesRoot = "/" },
		"names":      func(d *PolicyDoc) { d.Names = append(slices.Clone(d.Names), "other-*") },
		"images":     func(d *PolicyDoc) { d.Images = append(slices.Clone(d.Images), "evil/*") },
		"networks":   func(d *PolicyDoc) { d.Networks = append(slices.Clone(d.Networks), "host") },
		"ports":      func(d *PolicyDoc) { d.Ports = append(slices.Clone(d.Ports), "1-65535/tcp") },
		"labels":     func(d *PolicyDoc) { d.Labels = append(slices.Clone(d.Labels), "x=y") },
		"exec":       func(d *PolicyDoc) { d.Exec = true },
		"max_scopes": func(d *PolicyDoc) { d.MaxScopes = 1000 },
	}
	for name, f := range widen {
		d := base
		f(&d)
		if name == "exec" && base.Exec {
			continue // already on: nothing to widen
		}
		if err := m.SetPolicy(d); err == nil {
			t.Errorf("%s: a widening edit was saved", name)
		}
	}
	if kept, _ := m.Policy(); !slices.Equal(kept.Policy.Names, base.Names) || kept.Policy.MaxScopes != base.MaxScopes {
		t.Errorf("a refused edit changed the file: %+v", kept.Policy)
	}
	same := base // saving what is already there is fine
	if err := m.SetPolicy(same); err != nil {
		t.Errorf("an unchanged save was refused: %v", err)
	}
}

func TestAllowingAModuleAddsItsPortsAndTurnOffIsGuarded(t *testing.T) {
	m, _ := newManager(t)
	if err := m.SetAllowed("not-a-module", true); err == nil {
		t.Error("an unknown module was allowed")
	}
	if err := m.SetAllowed("minecraft", true); err != nil {
		t.Fatal(err)
	}
	if err := m.SetAllowed("minecraft", true); err != nil {
		t.Errorf("allowing twice: %v", err)
	}
	if got, _ := m.Allowed(); len(got) != 1 || got[0] != "minecraft" {
		t.Fatalf("allowed %v", got)
	}
	var mc ModuleInfo
	for _, mi := range m.Catalogue() {
		if mi.ID == "minecraft" {
			mc = mi
		}
	}
	if !mc.Allowed || !mc.Bundled || len(mc.PortNotes) == 0 || mc.PortNotes[0].Why == "" {
		t.Errorf("catalogue entry: %+v", mc)
	}
	// The policy view shows only what the file says, so a save never writes the module's ports into it.
	st, err := m.Policy()
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(st.Policy.Ports, "25565/tcp") != slices.Contains(strings.Fields(strings.NewReplacer(`"`, " ", `[`, " ", `]`, " ", `,`, " ").Replace(policy)), "25565/tcp") {
		t.Errorf("policy view ports %v include the allowed module's ports", st.Policy.Ports)
	}
	m.entries = append(m.entries, &entry{Request: Request{ID: "mc1", Module: "minecraft"}})
	if err := m.SetAllowed("minecraft", false); err == nil || !strings.Contains(err.Error(), "mc1") {
		t.Errorf("turned off with a game still there: %v", err)
	}
	m.entries = nil
	if err := m.SetAllowed("minecraft", false); err != nil {
		t.Fatal(err)
	}
}

// A second game of one module gets the next free host port without being asked;
// a port typed by hand that clashes is still refused.
func TestSecondGameGetsNextFreePort(t *testing.T) {
	m, _ := newManager(t)
	first := Request{ID: "minecraft", Module: "minecraft", Options: map[string]string{"eula": "TRUE"}, Secrets: map[string]string{"rcon_password": "x"}}
	if err := m.Enable(first); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "minecraft", StateReady)
	second := Request{ID: "gs-two", Module: "minecraft", Options: map[string]string{"eula": "TRUE"}, Secrets: map[string]string{"rcon_password": "x"}}
	plan, err := m.Preview(second)
	if err != nil || !plan.Fits {
		t.Fatalf("preview: %+v %v", plan, err)
	}
	if !strings.Contains(strings.Join(plan.Ports, " "), "25566:25565") {
		t.Errorf("ports %v, want host 25566", plan.Ports)
	}
	second.Options["ports"] = "25565:25565/tcp"
	if _, err := m.Preview(second); err == nil || !strings.Contains(err.Error(), "already used by minecraft") {
		t.Errorf("a hand-typed clash was not refused: %v", err)
	}
	// Outside the policy's ports there is nothing to suggest, and the clash says so.
	delete(second.Options, "ports")
	m.entries[0].rendered.Scope.Ports = append(m.entries[0].rendered.Scope.Ports, modules.GuardPort{HostIP: "10.0.0.2", HostPort: "25566", Proto: "tcp"})
	for p := 25567; p <= 26000; p++ {
		m.entries[0].rendered.Scope.Ports = append(m.entries[0].rendered.Scope.Ports, modules.GuardPort{HostIP: "10.0.0.2", HostPort: strconv.Itoa(p), Proto: "tcp"})
	}
	if _, err := m.Preview(second); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("with the range full: %v", err)
	}
}

// A module installed from outside is offered only once switched on, and the
// guard never takes its image or ports from it: the policy still has to.
func TestInstalledModuleNeedsItsSwitchAndThePolicy(t *testing.T) {
	m, _ := newManager(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "mygame"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../docs/examples/mygame/module.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mygame", "module.yaml"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Modules.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	find := func() ModuleInfo {
		for _, mi := range m.Catalogue() {
			if mi.ID == "mygame" {
				return mi
			}
		}
		t.Fatal("mygame is not in the catalogue")
		return ModuleInfo{}
	}
	mi := find()
	if !mi.Gated || mi.Allowed || mi.Fits == nil || *mi.Fits || !strings.Contains(mi.PolicyLines, "example/mygame-server") || !strings.Contains(mi.PolicyLines, "7777/udp") {
		t.Errorf("before the switch: %+v", mi)
	}
	req := Request{ID: "mygame", Module: "mygame", Options: map[string]string{}}
	if _, err := m.Preview(req); err == nil || !strings.Contains(err.Error(), "not switched on") {
		t.Errorf("a game from an off module: %v", err)
	}
	if err := m.SetAllowed("mygame", true); err != nil {
		t.Fatal(err)
	}
	// On, but the policy does not name its image or ports yet: the plan says so rather than the guard accepting it.
	plan, err := m.Preview(req)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Fits {
		t.Errorf("the guard would accept an image and port the policy never listed: %+v", plan)
	}
}

// With a shared backups folder, an enabled game gets its own folder in it
// (made by the panel, not Docker), the panel lists it itself, and the exec
// guard is not asked to allow a listing or prune command for it.
func TestSharedBackupsFolderPerGame(t *testing.T) {
	m, fd := newManager(t)
	root := t.TempDir()
	pol, _ := os.ReadFile(m.PolicyFile)
	pol = []byte(strings.Replace(string(pol), "names: [", "names: [minecraft-2, minecraft-3, ", 1))
	if err := os.WriteFile(m.PolicyFile, append(pol, []byte("\nbackups_root: /mnt/usb/backups\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	m.Platform.BackupsRoot, m.Platform.BackupsMount = "/mnt/usb/backups", root
	m.Backups = &backup.Root{Mount: root, Mode: 0o775, StateFile: filepath.Join(t.TempDir(), "state"), ConfirmNew: true}

	for _, id := range []string{"minecraft", "minecraft-2"} {
		req := Request{ID: id, Module: "minecraft", Options: map[string]string{"eula": "TRUE"}, Secrets: map[string]string{"rcon_password": "x"}}
		if id == "minecraft-2" {
			req.Options["ports"] = "25566:25565/tcp"
		}
		if err := m.Enable(req); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		waitState(t, m, id, StateReady)
		if fi, err := os.Stat(filepath.Join(root, id)); err != nil || !fi.IsDir() {
			t.Errorf("%s: the panel did not create its backup folder: %v", id, err)
		}
		g, ok := m.Registry.Get(id)
		if !ok || g.Backup == nil || g.Backup.LocalDir != filepath.Join(root, id) {
			t.Errorf("%s: backup spec = %+v", id, g.Backup)
		}
	}
	_ = fd
	rules, err := ExecRulesFor(m.Dir, m.PolicyFile, m.Modules, true)
	if err != nil || len(rules) != 2 { // each game's backup command only
		t.Fatalf("rules = %+v, %v", rules, err)
	}
	for _, r := range rules {
		if strings.Contains(strings.Join(r.Cmd, " "), "find ") {
			t.Errorf("a listing command is allowlisted although the panel reads the folder itself: %v", r.Cmd)
		}
	}

	// Each game has a restore container of its own: <id>-restore, from its image,
	// with its folders; the guard loads those scopes under the same policy.
	if spec, ok := m.RestoreSpec("minecraft-2", "manual-1.tgz"); !ok || spec.Name != "minecraft-2-restore" ||
		!strings.Contains(strings.Join(spec.Binds, " "), "/mnt/usb/backups/minecraft-2:/data/backups:ro") {
		t.Errorf("restore spec = %+v, %v", spec, ok)
	}
	if _, ok := m.RestoreSpec("nope", "x.tgz"); ok {
		t.Error("a restore spec for a game that is not managed")
	}
	res, lerr := dockerguard.Sources{ManagedFile: m.path("scopes.json"), PolicyFile: m.PolicyFile, AllowedFile: dockerguard.AllowedPath(m.path("scopes.json"))}.Load()
	if lerr != nil || len(res.Rejected) > 0 {
		t.Fatalf("the guard rejected the scopes: %v %v", lerr, res)
	}
	names := map[string]bool{}
	for _, sc := range res.Scopes {
		names[sc.Name] = true
	}
	if !names["minecraft-restore"] || !names["minecraft-2-restore"] {
		t.Errorf("scopes in force = %v", names)
	}
	if err := m.Enable(Request{ID: "mc-restore", Module: "minecraft", Options: map[string]string{"eula": "TRUE"}}); err == nil ||
		!strings.Contains(err.Error(), "-restore") {
		t.Errorf("an id ending in -restore was accepted: %v", err)
	}

	// A drive that went missing stops the next game being created on it.
	_ = os.Remove(filepath.Join(root, ".crowsnest-backups"))
	err = m.Enable(Request{ID: "minecraft-3", Module: "minecraft", Options: map[string]string{"eula": "TRUE", "ports": "25567:25565/tcp"},
		Secrets: map[string]string{"rcon_password": "x"}})
	if err == nil {
		waitState(t, m, "minecraft-3", StateFailed)
	}
}
