package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoad_Valid(t *testing.T) {
	path := writeConfig(t, `
server:
  addr: ":8080"
  session_secret_file: /app/.session_secret
  tz: "America/New_York"
  trusted_proxies: ["10.0.0.0/8", "172.16.0.0/12"]

idle_shutdown:
  enabled: true
  idle_minutes: 20
  check_interval_seconds: 45

users_file: /app/users.env

games:
  - id: windrose
    display_name: Windrose
    container_name: windrose
    compose_file: /windrose/compose.yaml
    compose_profile: windrose
    compose_service: windrose
    env_file: /windrose/.env
    windrose:
      http_api_url: http://host.docker.internal:8780
      rcon_password_env: WINDROSE_PLUS_RCON_PASSWORD
  - id: valheim
    display_name: Valheim
    container_name: valheim
    compose_file: /valheim/compose.yaml
    compose_profile: valheim
    compose_service: valheim
  - id: palworld
    display_name: Palworld
    container_name: palworld
    compose_file: /palworld/compose.yaml
    compose_profile: palworld
    compose_service: palworld
    palworld:
      rest_api_url: http://palworld:8212
      rest_api_user: admin
      rest_api_password_env: PALWORLD_ADMIN_PASSWORD
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.Addr != ":8080" {
		t.Errorf("Server.Addr = %q, want :8080", cfg.Server.Addr)
	}
	if cfg.Server.TZ != "America/New_York" {
		t.Errorf("Server.TZ = %q, want America/New_York", cfg.Server.TZ)
	}
	wantProxies := []string{"10.0.0.0/8", "172.16.0.0/12"}
	if len(cfg.Server.TrustedProxies) != len(wantProxies) ||
		cfg.Server.TrustedProxies[0] != wantProxies[0] || cfg.Server.TrustedProxies[1] != wantProxies[1] {
		t.Errorf("Server.TrustedProxies = %v, want %v", cfg.Server.TrustedProxies, wantProxies)
	}
	if cfg.IdleShutdown.IdleMinutes != 20 || cfg.IdleShutdown.CheckIntervalSeconds != 45 || !cfg.IdleShutdown.Enabled {
		t.Errorf("IdleShutdown = %+v, want {true 20 45}", cfg.IdleShutdown)
	}
	if len(cfg.Games) != 3 {
		t.Fatalf("len(Games) = %d, want 3", len(cfg.Games))
	}

	wr := cfg.Games[0]
	if wr.ID != "windrose" || wr.ContainerName != "windrose" || wr.ComposeService != "windrose" {
		t.Errorf("Games[0] = %+v", wr)
	}
	if wr.Windrose == nil || wr.Windrose.HTTPAPIURL != "http://host.docker.internal:8780" {
		t.Errorf("Games[0].Windrose = %+v", wr.Windrose)
	}

	pw := cfg.Games[2]
	if pw.Palworld == nil || pw.Palworld.RESTAPIUser != "admin" {
		t.Errorf("Games[2].Palworld = %+v", pw.Palworld)
	}
}

func TestLoad_Defaults(t *testing.T) {
	path := writeConfig(t, `
users_file: /app/users.env
games:
  - id: windrose
    display_name: Windrose
    container_name: windrose
    compose_file: /windrose/compose.yaml
    compose_profile: windrose
    compose_service: windrose
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.Addr != defaultAddr {
		t.Errorf("Server.Addr = %q, want %q", cfg.Server.Addr, defaultAddr)
	}
	if cfg.Server.SessionSecretFile != defaultSessionKeyFile {
		t.Errorf("Server.SessionSecretFile = %q, want %q", cfg.Server.SessionSecretFile, defaultSessionKeyFile)
	}
	if cfg.Server.TZ != defaultTZ {
		t.Errorf("Server.TZ = %q, want %q", cfg.Server.TZ, defaultTZ)
	}
	want := IdleShutdownConfig{Enabled: true, IdleMinutes: defaultIdleMinutes, CheckIntervalSeconds: defaultCheckIntervalSeconds}
	if *cfg.IdleShutdown != want {
		t.Errorf("IdleShutdown = %+v, want %+v", *cfg.IdleShutdown, want)
	}
	wantNight := NightShutdownConfig{
		Enabled:              false,
		StartHour:            defaultNightShutdownStartHour,
		EndHour:              defaultNightShutdownEndHour,
		CheckIntervalMinutes: defaultNightShutdownCheckIntervalMinutes,
		MinUptimeMinutes:     defaultNightShutdownMinUptimeMinutes,
	}
	if *cfg.NightShutdown != wantNight {
		t.Errorf("NightShutdown = %+v, want %+v", *cfg.NightShutdown, wantNight)
	}
	if cfg.Notifications == nil || cfg.Notifications.DiscordWebhookURLEnv != "" {
		t.Errorf("Notifications = %+v, want an empty (disabled) block", cfg.Notifications)
	}
}

func TestLoad_NightShutdownAndNotifications(t *testing.T) {
	path := writeConfig(t, `
users_file: /app/users.env
night_shutdown:
  enabled: true
  start_hour: 22
  end_hour: 6
  check_interval_minutes: 15
notifications:
  discord_webhook_url_env: DISCORD_WEBHOOK_URL
games:
  - id: windrose
    display_name: Windrose
    container_name: windrose
    compose_file: /windrose/compose.yaml
    compose_profile: windrose
    compose_service: windrose
  - id: palworld
    display_name: Palworld
    container_name: palworld
    compose_file: /palworld/compose.yaml
    compose_profile: palworld
    compose_service: palworld
    night_shutdown: false
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := NightShutdownConfig{Enabled: true, StartHour: 22, EndHour: 6, CheckIntervalMinutes: 15, MinUptimeMinutes: 30}
	if *cfg.NightShutdown != want {
		t.Errorf("NightShutdown = %+v, want %+v", *cfg.NightShutdown, want)
	}
	if cfg.Notifications.DiscordWebhookURLEnv != "DISCORD_WEBHOOK_URL" {
		t.Errorf("Notifications.DiscordWebhookURLEnv = %q, want DISCORD_WEBHOOK_URL", cfg.Notifications.DiscordWebhookURLEnv)
	}
	if cfg.Games[0].NightShutdown != nil {
		t.Errorf("Games[0].NightShutdown = %v, want nil (included by default)", cfg.Games[0].NightShutdown)
	}
	if cfg.Games[1].NightShutdown == nil || *cfg.Games[1].NightShutdown {
		t.Errorf("Games[1].NightShutdown = %v, want explicit false", cfg.Games[1].NightShutdown)
	}
}

func TestLoad_InvalidNightShutdownHours(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "start hour out of range",
			yaml: `
users_file: /app/users.env
night_shutdown:
  start_hour: 24
games:
  - id: a
    display_name: A
    container_name: a
    compose_file: f
    compose_profile: p
    compose_service: s
`,
			wantErr: "start_hour",
		},
		{
			name: "invalid timezone",
			yaml: `
server:
  tz: "Not/A/Zone"
users_file: /app/users.env
games:
  - id: a
    display_name: A
    container_name: a
    compose_file: f
    compose_profile: p
    compose_service: s
`,
			wantErr: "server.tz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, tt.yaml)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_PartialIdleShutdownKeepsExplicitValues(t *testing.T) {
	path := writeConfig(t, `
users_file: /app/users.env
idle_shutdown:
  enabled: false
games:
  - id: windrose
    display_name: Windrose
    container_name: windrose
    compose_file: /windrose/compose.yaml
    compose_profile: windrose
    compose_service: windrose
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.IdleShutdown.Enabled {
		t.Error("IdleShutdown.Enabled = true, want false (explicit block should not be overridden)")
	}
	if cfg.IdleShutdown.IdleMinutes != defaultIdleMinutes {
		t.Errorf("IdleShutdown.IdleMinutes = %d, want default %d filled in", cfg.IdleShutdown.IdleMinutes, defaultIdleMinutes)
	}
}

func TestLoad_Errors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "no games",
			yaml:    "users_file: /app/users.env\ngames: []\n",
			wantErr: "at least one game must be defined",
		},
		{
			name:    "missing users_file",
			yaml:    "games:\n  - id: a\n    display_name: A\n    container_name: a\n    compose_file: f\n    compose_profile: p\n    compose_service: s\n",
			wantErr: "users_file is required",
		},
		{
			name: "invalid trusted proxy CIDR",
			yaml: `
server:
  trusted_proxies: ["not-a-cidr"]
users_file: /app/users.env
games:
  - id: a
    display_name: A
    container_name: a
    compose_file: f
    compose_profile: p
    compose_service: s
`,
			wantErr: "trusted_proxies[0]",
		},
		{
			name: "duplicate id",
			yaml: `
users_file: /app/users.env
games:
  - id: a
    display_name: A
    container_name: a1
    compose_file: f
    compose_profile: p
    compose_service: s
  - id: a
    display_name: A2
    container_name: a2
    compose_file: f
    compose_profile: p
    compose_service: s
`,
			wantErr: "duplicate id",
		},
		{
			name: "duplicate container name",
			yaml: `
users_file: /app/users.env
games:
  - id: a
    display_name: A
    container_name: shared
    compose_file: f
    compose_profile: p
    compose_service: s
  - id: b
    display_name: B
    container_name: shared
    compose_file: f
    compose_profile: p
    compose_service: s
`,
			wantErr: "already used by game",
		},
		{
			name: "invalid id",
			yaml: `
users_file: /app/users.env
games:
  - id: Not_Valid
    display_name: A
    container_name: a
    compose_file: f
    compose_profile: p
    compose_service: s
`,
			wantErr: "id must match",
		},
		{
			name: "missing compose_profile",
			yaml: `
users_file: /app/users.env
games:
  - id: a
    display_name: A
    container_name: a
    compose_file: f
    compose_service: s
`,
			wantErr: "compose_profile is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, tt.yaml)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("Load() error = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("Load() error = nil, want error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeConfig(t, "games: [this is not: valid: yaml\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want parse error")
	}
}

func TestLoad_MaxActiveGames(t *testing.T) {
	const base = "users_file: /u\ngames:\n  - {id: a, display_name: A, container_name: a, compose_file: /c.yaml, compose_profile: a, compose_service: a}\n"
	load := func(yaml, env string) (*Config, error) {
		t.Setenv(MaxActiveGamesEnv, env)
		return Load(writeConfig(t, yaml))
	}

	if cfg, err := load(base, ""); err != nil || cfg.Server.MaxActiveGames != 1 {
		t.Fatalf("default = %v, %v; want 1", cfg, err)
	}
	if cfg, err := load("server: {max_active_games: 2}\n"+base, ""); err != nil || cfg.Server.MaxActiveGames != 2 {
		t.Fatalf("yaml 2 = %v, %v; want 2", cfg, err)
	}
	if cfg, err := load("server: {max_active_games: 2}\n"+base, "3"); err != nil || cfg.Server.MaxActiveGames != 3 {
		t.Fatalf("env override = %v, %v; want 3", cfg, err)
	}
	for _, bad := range []string{"0", "-1", "two"} {
		if _, err := load(base, bad); err == nil {
			t.Errorf("env %q accepted, want error", bad)
		}
	}
}

func TestLoad_ConnectSecrets(t *testing.T) {
	base := `
users_file: /app/users.env
games:
  - id: palworld
    display_name: Palworld
    container_name: palworld
    compose_file: /palworld/compose.yaml
    compose_profile: palworld
    compose_service: palworld
    connect_secrets:
%s`
	cfg, err := Load(writeConfig(t, fmt.Sprintf(base, "      - {label: Join password, env: PALWORLD_SERVER_PASSWORD}\n")))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Games[0].ConnectSecrets; len(got) != 1 || got[0].Label != "Join password" || got[0].Env != "PALWORLD_SERVER_PASSWORD" {
		t.Errorf("ConnectSecrets = %+v", got)
	}
	if _, err := Load(writeConfig(t, fmt.Sprintf(base, "      - {label: Join password}\n"))); err == nil {
		t.Error("connect_secrets entry without env accepted, want error")
	}
}

func TestLoad_ConnectDetails(t *testing.T) {
	path := writeConfig(t, `
users_file: /app/users.env
games:
  - id: palworld
    display_name: Palworld
    container_name: palworld
    compose_file: /palworld/compose.yaml
    compose_profile: palworld
    compose_service: palworld
    connect_address: "play.example.com:8211"
    connect_note: "Password is in our group chat"
  - id: valheim
    display_name: Valheim
    container_name: valheim
    compose_file: /valheim/compose.yaml
    compose_profile: valheim
    compose_service: valheim
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if g := cfg.Games[0]; g.ConnectAddress != "play.example.com:8211" || g.ConnectNote != "Password is in our group chat" {
		t.Errorf("Games[0] connect = %q / %q", g.ConnectAddress, g.ConnectNote)
	}
	if g := cfg.Games[1]; g.ConnectAddress != "" || g.ConnectNote != "" {
		t.Errorf("Games[1] connect = %q / %q, want both empty when unset", g.ConnectAddress, g.ConnectNote)
	}
}

const authTestGames = `
users_file: /app/users.env
games:
  - id: a
    display_name: A
    container_name: a
    compose_file: f
    compose_profile: p
    compose_service: s
`

func TestLoad_AuthGoogle(t *testing.T) {
	path := writeConfig(t, `
server:
  secure_cookies: true
auth:
  password_login: false
  google:
    redirect_url: https://crowsnest.example.com/auth/google/callback
`+authTestGames)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Auth.PasswordLoginEnabled() {
		t.Fatal("password_login: false should disable password sign-in")
	}
	g := cfg.Auth.Google
	if g.ClientIDEnv != "CROWSNEST_GOOGLE_CLIENT_ID" || g.ClientSecretEnv != "CROWSNEST_GOOGLE_CLIENT_SECRET" || g.UsersEnv != "CROWSNEST_GOOGLE_USERS" {
		t.Fatalf("default env names = %+v", g)
	}

	path = writeConfig(t, authTestGames)
	if cfg, err = Load(path); err != nil || !cfg.Auth.PasswordLoginEnabled() || cfg.Auth.Google != nil {
		t.Fatalf("no auth section: err=%v, password=%v google=%v; want password on, google off", err, cfg.Auth.PasswordLoginEnabled(), cfg.Auth.Google)
	}
}

func TestLoad_AuthErrors(t *testing.T) {
	for name, tc := range map[string]struct{ auth, want string }{
		"nobody can sign in":      {"auth:\n  password_login: false\n", "nobody could sign in"},
		"no redirect":             {"auth:\n  google: {}\n", "redirect_url is required"},
		"relative redirect":       {"auth:\n  google:\n    redirect_url: /auth/google/callback\n", "absolute URL"},
		"plain http":              {"auth:\n  google:\n    redirect_url: http://crowsnest.example.com/auth/google/callback\n", "must be https"},
		"wrong path":              {"auth:\n  google:\n    redirect_url: https://crowsnest.example.com/callback\n", "path must be"},
		"query":                   {"auth:\n  google:\n    redirect_url: https://crowsnest.example.com/auth/google/callback?x=1\n", "no query"},
		"empty query":             {"auth:\n  google:\n    redirect_url: https://crowsnest.example.com/auth/google/callback?\n", "no query"},
		"empty fragment":          {"auth:\n  google:\n    redirect_url: \"https://crowsnest.example.com/auth/google/callback#\"\n", "no query"},
		"escaped path":            {"auth:\n  google:\n    redirect_url: https://crowsnest.example.com/auth%2Fgoogle/callback\n", "no query"},
		"https, insecure cookies": {"auth:\n  google:\n    redirect_url: https://crowsnest.example.com/auth/google/callback\n", "secure_cookies must be true"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.auth+authTestGames))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	if _, err := Load(writeConfig(t, "auth:\n  google:\n    redirect_url: http://localhost:5000/auth/google/callback\n"+authTestGames)); err != nil {
		t.Fatalf("http://localhost redirect should be allowed for local testing: %v", err)
	}
}

func TestLoad_BackupValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		backup  string
		wantErr string
	}{
		"ok":         {"    backup:\n      exec: [\"/bin/sh\", \"-c\", \"backup\"]\n      list_dir: /backups\n", ""},
		"no command": {"    backup:\n      list_dir: /backups\n", "backup.exec"},
		"relative":   {"    backup:\n      exec: [backup]\n      list_dir: backups\n", "absolute"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			os.WriteFile(path, []byte("users_file: /tmp/users.env\ngames:\n  - id: g\n    display_name: G\n    container_name: g\n    compose_file: /data/c.yaml\n    compose_service: g\n    compose_profile: g\n"+tc.backup), 0o600)
			_, err := Load(path)
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Load error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestLegacyBlocksFoldIntoOptions(t *testing.T) {
	c := &Config{Games: []GameConfig{
		{ID: "windrose", Windrose: &WindroseConfig{HTTPAPIURL: "http://w:8780", RCONPasswordEnv: "WR_PW"}},
		{ID: "palworld", Palworld: &PalworldConfig{RESTAPIURL: "http://p:8212", RESTAPIUser: "admin", RESTAPIPasswordEnv: "ADMIN", RCONAddr: "p:25575"}},
		{ID: "pal2", Options: map[string]string{"rest_api_url": "explicit"}, Palworld: &PalworldConfig{RESTAPIURL: "legacy"}},
		{ID: "pal3", Palworld: &PalworldConfig{RESTAPIURL: "http://p:8212", RESTAPIPasswordEnv: "ADMIN"}},
	}}
	c.foldLegacyOptions()
	w, p, p2, p3 := c.Games[0].Options, c.Games[1].Options, c.Games[2].Options, c.Games[3].Options
	if w["http_api_url"] != "http://w:8780" || w["rcon_password_env"] != "WR_PW" {
		t.Errorf("windrose options = %v", w)
	}
	if p["rest_api_url"] != "http://p:8212" || p["rcon_addr"] != "p:25575" || p["rcon_password_env"] != "ADMIN" {
		t.Errorf("palworld options = %v (rcon password must default to the REST one)", p)
	}
	if p2["rest_api_url"] != "explicit" {
		t.Errorf("explicit option must win, got %v", p2)
	}
	if _, set := p3["rcon_password_env"]; set {
		t.Errorf("no rcon_addr: rcon_password_env must not be set, got %v", p3)
	}
}
