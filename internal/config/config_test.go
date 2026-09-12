package config

import (
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
	if cfg.Server.SessionSecretFile != defaultSessionSecretFile {
		t.Errorf("Server.SessionSecretFile = %q, want %q", cfg.Server.SessionSecretFile, defaultSessionSecretFile)
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
	want := NightShutdownConfig{Enabled: true, StartHour: 22, EndHour: 6, CheckIntervalMinutes: 15}
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
