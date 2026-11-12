package modules

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerguard"
	"gopkg.in/yaml.v3"
)

var labTestPlatform = Platform{GamesRoot: "${USERDIR}", HostIP: "10.0.0.2"}

func renderBundled(t *testing.T, g config.GameConfig) *Rendered {
	t.Helper()
	id := g.ID
	if g.Module != "" {
		id = g.Module
	}
	m, ok := Bundled().Manifest(id)
	if !ok {
		t.Fatalf("no manifest %q", id)
	}
	r, err := m.Render(g, labTestPlatform)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The rendered Valheim and Palworld services must say exactly what the
// hand-written games.compose.yaml and GUARD_SCOPES in production say today,
// so moving to generated files changes nothing about the running servers.
func TestRenderMatchesHandWrittenValheim(t *testing.T) {
	r := renderBundled(t, config.GameConfig{ID: "valheim", ContainerName: "valheim"})
	s := r.Service
	if s.Image != "lloesche/valheim-server:latest" || s.ContainerName != "valheim" || s.Restart != "unless-stopped" || s.StopGrace != "2m" {
		t.Errorf("service header: %+v", s)
	}
	eq := func(name string, got, want any) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	eq("ports", s.Ports, []string{"10.0.0.2:2456:2456/udp", "10.0.0.2:2457:2457/udp"})
	eq("volumes", s.Volumes, []string{"${USERDIR}/Valheim/config:/config", "${USERDIR}/Valheim/data:/opt/valheim"})
	eq("networks", s.Networks, []string{"crowsnest-games-net"})
	eq("env", s.Environment, []string{
		"TZ=${TZ:-UTC}",
		"PUID=1000", // added on purpose: as root the image took the shared backups folder from the panel
		"PGID=1000",
		"SERVER_NAME=${VALHEIM_SERVER_NAME:-My Valheim Server}",
		"WORLD_NAME=${VALHEIM_WORLD_NAME:-Midgard}",
		"SERVER_PASS=${VALHEIM_SERVER_PASS:-}",
		"SERVER_PUBLIC=${VALHEIM_SERVER_PUBLIC:-false}",
		"BACKUPS_MAX_AGE=${VALHEIM_BACKUPS_MAX_AGE:-3}",
	})
	b, _ := json.Marshal(r.Scope)
	want := `{"name":"valheim","images":["lloesche/valheim-server"],"binds":["${USERDIR}/Valheim/config","${USERDIR}/Valheim/data"],` +
		`"networks":["crowsnest-games-net"],"ports":[{"host_ip":"10.0.0.2","host_port":"2456","container_port":"2456","proto":"udp"},` +
		`{"host_ip":"10.0.0.2","host_port":"2457","container_port":"2457","proto":"udp"}],` +
		`"labels":{"com.centurylinklabs.watchtower.enable":"false","crowsnest.managed":"true"},"exec":true}`
	if string(b) != want {
		t.Errorf("scope:\n got %s\nwant %s", b, want)
	}
}

func TestRenderMatchesHandWrittenPalworld(t *testing.T) {
	r := renderBundled(t, config.GameConfig{ID: "palworld", ContainerName: "palworld"})
	s := r.Service
	if s.Image != "thijsvanloef/palworld-server-docker:latest" || s.MemLimit != "10g" || s.StopGrace != "1m" {
		t.Errorf("service: %+v", s) // 60s is written 1m: identical to compose
	}
	if !reflect.DeepEqual(s.Ports, []string{"10.0.0.2:8211:8211/udp"}) || !reflect.DeepEqual(s.Volumes, []string{"${USERDIR}/Palworld:/palworld"}) {
		t.Errorf("ports/volumes: %v %v", s.Ports, s.Volumes)
	}
	for _, want := range []string{
		"PLAYERS=${PALWORLD_MAX_PLAYERS:-8}", "SERVER_NAME=${PALWORLD_SERVER_NAME:-CrowsNest Palworld}",
		"SERVER_PASSWORD=${PALWORLD_SERVER_PASSWORD:-}", "ADMIN_PASSWORD=${PALWORLD_ADMIN_PASSWORD:-}",
		"REST_API_ENABLED=true", "RCON_ENABLED=false", "OLD_BACKUP_DAYS=14",
	} {
		found := false
		for _, e := range s.Environment {
			found = found || e == want
		}
		if !found {
			t.Errorf("env lacks %q", want)
		}
	}
}

// Generated scopes must be accepted by the real guard loader, and the compose
// file must be valid YAML with one service per game.
func TestRenderedFilesAreValid(t *testing.T) {
	rs := []*Rendered{
		renderBundled(t, config.GameConfig{ID: "valheim", ContainerName: "valheim"}),
		renderBundled(t, config.GameConfig{ID: "minecraft", ContainerName: "minecraft", Options: map[string]string{"eula": "TRUE", "motd": "it's $5"}}),
	}
	js, err := ScopesJSON(rs)
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := dockerguard.LoadScopes(strings.ReplaceAll(string(js), "${USERDIR}", "/srv/games"))
	if err != nil || len(scopes) != 4 { // each game and its data cleaner
		t.Fatalf("guard rejected the scopes: %v\n%s", err, js)
	}
	cf, err := ComposeFile(rs, "")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Environment []string `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(cf, &doc); err != nil || len(doc.Services) != 2 {
		t.Fatalf("compose: %v\n%s", err, cf)
	}
	env := strings.Join(doc.Services["minecraft"].Environment, "|")
	if !strings.Contains(env, "EULA=TRUE") || !strings.Contains(env, "MOTD=it's $$5") {
		t.Errorf("instance values / $ escaping wrong: %s", env)
	}
	if !strings.Contains(env, "RCON_PASSWORD=${MINECRAFT_RCON_PASSWORD:-}") {
		t.Errorf("secret must stay a .env reference: %s", env)
	}
}

func TestRenderSecretsNeverInline(t *testing.T) {
	g := config.GameConfig{ID: "valheim", ContainerName: "valheim", Options: map[string]string{"server_pass": "hunter22"}}
	r := renderBundled(t, g)
	if strings.Contains(strings.Join(r.Service.Environment, "|"), "hunter22") {
		t.Fatal("a secret option value was written into the compose file")
	}
}

func TestRenderRejects(t *testing.T) {
	m, _ := Bundled().Manifest("valheim")
	for name, g := range map[string]config.GameConfig{
		"escape":    {ID: "valheim", ContainerName: "v", Options: map[string]string{"data_dir": "../etc"}},
		"abs":       {ID: "valheim", ContainerName: "v", Options: map[string]string{"data_dir": "/etc"}},
		"bad port":  {ID: "valheim", ContainerName: "v", Options: map[string]string{"ports": "99999"}},
		"bad proto": {ID: "valheim", ContainerName: "v", Options: map[string]string{"ports": "27015/icmp"}},
	} {
		if _, err := m.Render(g, labTestPlatform); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := m.Render(config.GameConfig{ID: "valheim"}, Platform{}); err == nil {
		t.Error("missing games_root accepted")
	}
	src, _ := Bundled().Manifest("source")
	if _, err := src.Render(config.GameConfig{ID: "tf2", ContainerName: "tf2", Module: "source"}, labTestPlatform); err == nil {
		t.Error("source has no image; rendering without options.image must fail")
	}
	r, err := src.Render(config.GameConfig{ID: "tf2", ContainerName: "tf2", Module: "source",
		Options: map[string]string{"image": "cm2network/tf2", "ports": "27015/udp,27015/tcp", "data_dir": "TF2"}}, labTestPlatform)
	if err != nil || len(r.Service.Ports) != 2 || r.Service.Image != "cm2network/tf2:latest" {
		t.Errorf("per-instance image/ports: %v %+v", err, r)
	}
}

// Everything render produces for the games the lab runs fits an operator
// policy, with the games root given as a variable for compose and as a literal
// path for the guard. Pushing a port or bind outside the policy does not.
func TestRenderedScopesFitPolicy(t *testing.T) {
	plat := Platform{GamesRoot: "${USERDIR}", HostGamesRoot: "/srv/games", HostIP: "10.0.0.2"}
	pol, err := dockerguard.ParsePolicy([]byte(`
games_root: /srv/games
names: [valheim, palworld, minecraft]
images: [lloesche/valheim-server, thijsvanloef/palworld-server-docker, docker.io/itzg/*]
networks: [crowsnest-games-net]
ports: ["2000-30000/udp", "25565/tcp"]
host_ips: [10.0.0.2]
exec: true
`))
	if err != nil {
		t.Fatal(err)
	}
	admit := func(g config.GameConfig) error {
		m, _ := Bundled().Manifest(g.ID)
		r, err := m.Render(g, plat)
		if err != nil {
			t.Fatal(err)
		}
		js, _ := ScopesJSON([]*Rendered{r})
		scopes, err := dockerguard.LoadScopes(string(js))
		if err != nil {
			t.Fatalf("guard rejected %s: %v\n%s", g.ID, err, js)
		}
		return pol.Admit(scopes[0])
	}
	for _, id := range []string{"valheim", "palworld", "minecraft"} {
		if err := admit(config.GameConfig{ID: id, ContainerName: id}); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
	if err := admit(config.GameConfig{ID: "valheim", ContainerName: "valheim", Options: map[string]string{"ports": "22:2456/udp"}}); err == nil {
		t.Error("a port outside the policy was admitted")
	}
	if err := admit(config.GameConfig{ID: "valheim", ContainerName: "valheim", Options: map[string]string{"image": "evil/miner"}}); err == nil {
		t.Error("an image outside the policy was admitted")
	}
}

// The dashboard path backs Valheim and Palworld up with the same commands
// config.yaml runs in production.
func TestBundledBackupsMatchProduction(t *testing.T) {
	want := map[string][]string{
		"palworld": {"backup"},
		"valheim":  {"/bin/sh", "-c", "mkdir -p /config/backups && tar czf /config/backups/manual-$(date +%Y%m%d-%H%M%S).tar.gz -C /config worlds_local"},
	}
	for id, cmd := range want {
		m, _ := Bundled().Manifest(id)
		if m.Backup == nil || strings.Join(m.Backup.Exec, "\x00") != strings.Join(cmd, "\x00") {
			t.Errorf("%s backup = %+v, want %v", id, m.Backup, cmd)
		}
	}
	if m, _ := Bundled().Manifest("minecraft"); m.Backup == nil || m.Backup.ExecListDir() != "/data/backups" {
		t.Errorf("minecraft backup = %+v", m.Backup)
	}
}

// A game with no backup command needs no exec, so the shipped policy
// (exec: false) must admit it; only a module that declares a backup asks
// for exec.
func TestScopeAsksForExecOnlyWithABackup(t *testing.T) {
	plat := Platform{GamesRoot: "${USERDIR}", HostGamesRoot: "/srv/games", HostIP: "10.0.0.2"}
	pol, err := dockerguard.ParsePolicy([]byte(`
games_root: /srv/games
images: [docker.io/itzg/*]
networks: [crowsnest-games-net]
ports: ["25565/tcp"]
host_ips: [10.0.0.2]
exec: false
`))
	if err != nil {
		t.Fatal(err)
	}
	admit := func(m *Manifest) error {
		r, err := m.Render(config.GameConfig{ID: "minecraft", ContainerName: "minecraft"}, plat)
		if err != nil {
			t.Fatal(err)
		}
		js, _ := ScopesJSON([]*Rendered{r})
		scopes, err := dockerguard.LoadScopes(string(js))
		if err != nil {
			t.Fatal(err)
		}
		return pol.Admit(scopes[0])
	}
	base, _ := Bundled().Manifest("minecraft")
	if base.Backup == nil {
		t.Fatal("minecraft should declare a backup")
	}
	if err := admit(base); err == nil {
		t.Error("a module with a backup was admitted while exec is off")
	}
	noBackup := *base
	noBackup.Backup = nil
	if err := admit(&noBackup); err != nil {
		t.Errorf("a module with no backup was refused while exec is off: %v", err)
	}
}

// Three servers of one game each get their own backup folder, named after the
// game id, bound at the module's backup dir and nowhere else.
func TestRenderBackupFolderPerGame(t *testing.T) {
	p := Platform{GamesRoot: "/srv/games", BackupsRoot: "${BACKUPS_DIR}", HostBackupsRoot: "/mnt/usb/backups", HostIP: "10.0.0.2"}
	m, _ := Bundled().Manifest("palworld")
	seen := map[string]bool{}
	for _, id := range []string{"palworld", "palworld-2", "palworld-friends"} {
		r, err := m.Render(config.GameConfig{ID: id, ContainerName: id, Options: map[string]string{"data_dir": id}}, p)
		if err != nil {
			t.Fatal(err)
		}
		wantVol := "${BACKUPS_DIR}/" + id + ":/palworld/backups"
		if !reflect.DeepEqual(r.Service.Volumes[len(r.Service.Volumes)-1:], []string{wantVol}) {
			t.Errorf("%s volumes = %v, want a final %s", id, r.Service.Volumes, wantVol)
		}
		wantBind := "/mnt/usb/backups/" + id
		if !containsStr(r.Scope.Binds, wantBind) || seen[wantBind] {
			t.Errorf("%s scope binds = %v, want %s once across games", id, r.Scope.Binds, wantBind)
		}
		seen[wantBind] = true
	}
	// No backups_root: nothing is bound, as before.
	r, _ := m.Render(config.GameConfig{ID: "palworld", ContainerName: "palworld"}, Platform{GamesRoot: "/srv/games"})
	for _, v := range r.Service.Volumes {
		if strings.Contains(v, "backups") {
			t.Errorf("a backups bind appeared without backups_root: %v", r.Service.Volumes)
		}
	}
	if got := p.BackupLocalDir("palworld-2"); got != "/game-backups/palworld-2" {
		t.Errorf("BackupLocalDir = %q", got)
	}
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestRenderRestoreContainer(t *testing.T) {
	p := Platform{GamesRoot: "/srv/games", BackupsRoot: "/mnt/usb/backups", HostIP: "10.0.0.2"}
	m, _ := Bundled().Manifest("minecraft")
	r, err := m.Render(config.GameConfig{ID: "mc-2", ContainerName: "mc-2", Options: map[string]string{"data_dir": "mc-2"}}, p)
	if err != nil {
		t.Fatal(err)
	}
	// The scope names <id>-restore with the game's image and folders, and no ports or exec.
	rs := r.RestoreScope
	if rs == nil || rs.Name != "mc-2-restore" || rs.Exec || len(rs.Ports) != 0 || !reflect.DeepEqual(rs.Binds, r.Scope.Binds) || !reflect.DeepEqual(rs.Images, r.Scope.Images) {
		t.Fatalf("restore scope = %+v (game scope %+v)", rs, r.Scope)
	}
	spec, ok := r.RestoreSpec("manual-1.tgz")
	if !ok || spec.Name != "mc-2-restore" || !spec.NoRestart || len(spec.Ports) != 0 || spec.Image != r.Service.Image {
		t.Fatalf("spec = %+v, %v", spec, ok)
	}
	if !reflect.DeepEqual(spec.Env, []string{"CROWSNEST_RESTORE_FILE=/data/backups/manual-1.tgz"}) {
		t.Errorf("env = %v", spec.Env)
	}
	if len(spec.Entrypoint) == 0 || spec.Entrypoint[0] != "/bin/sh" {
		t.Errorf("entrypoint = %v", spec.Entrypoint)
	}
	// The backups folder is read-only for the helper; the data folder is not.
	for _, b := range spec.Binds {
		ro := strings.HasSuffix(b, ":ro")
		if strings.Contains(b, "/mnt/usb/backups/") != ro {
			t.Errorf("bind %s: backups must be :ro and data must not be", b)
		}
	}
	if len(spec.Binds) != len(r.Scope.Binds) {
		t.Errorf("binds = %v, scope binds = %v", spec.Binds, r.Scope.Binds)
	}
	// ScopesJSON carries both scopes.
	b, _ := ScopesJSON([]*Rendered{r})
	if !strings.Contains(string(b), `"mc-2-restore"`) {
		t.Errorf("scopes JSON has no restore scope: %s", b)
	}
	// Without a shared folder, or for a module with no restore command, there is nothing.
	r2, _ := m.Render(config.GameConfig{ID: "mc-3", ContainerName: "mc-3"}, Platform{GamesRoot: "/srv/games"})
	if _, ok := r2.RestoreSpec("x.tgz"); ok || r2.RestoreScope != nil {
		t.Error("a restore container without a backups folder")
	}
	pal, _ := Bundled().Manifest("palworld")
	r3, _ := pal.Render(config.GameConfig{ID: "pal", ContainerName: "pal"}, p)
	if _, ok := r3.RestoreSpec("x.tgz"); ok || r3.RestoreScope != nil {
		t.Error("palworld has no verified restore command")
	}
}

func TestRenderCleanContainer(t *testing.T) {
	p := Platform{GamesRoot: "/srv/games", BackupsRoot: "/mnt/usb/backups", HostIP: "10.0.0.2"}
	m, _ := Bundled().Manifest("minecraft")
	r, err := m.Render(config.GameConfig{ID: "mc-2", ContainerName: "mc-2", Options: map[string]string{"data_dir": "mc-2"}}, p)
	if err != nil {
		t.Fatal(err)
	}
	cs := r.CleanScope
	if cs == nil || cs.Name != "mc-2-clean" || cs.Exec || len(cs.Ports) != 0 || !reflect.DeepEqual(cs.Images, r.Scope.Images) {
		t.Fatalf("clean scope = %+v", cs)
	}
	// Only the data folder: never the backups folder.
	if !reflect.DeepEqual(cs.Binds, []string{"/srv/games/mc-2"}) {
		t.Errorf("clean scope binds = %v", cs.Binds)
	}
	spec, ok := r.CleanSpec()
	if !ok || spec.Name != "mc-2-clean" || !spec.NoRestart || len(spec.Ports) != 0 || spec.Image != r.Service.Image {
		t.Fatalf("spec = %+v, %v", spec, ok)
	}
	if !reflect.DeepEqual(spec.Binds, []string{"/srv/games/mc-2:/data"}) {
		t.Errorf("binds = %v", spec.Binds)
	}
	want := []string{"/bin/sh", "-c", cleanScript, "sh", "/data"}
	if !reflect.DeepEqual(spec.Entrypoint, want) {
		t.Errorf("entrypoint = %v, want %v", spec.Entrypoint, want)
	}
	if b, _ := ScopesJSON([]*Rendered{r}); !strings.Contains(string(b), `"mc-2-clean"`) {
		t.Errorf("scopes JSON has no clean scope: %s", b)
	}
}
