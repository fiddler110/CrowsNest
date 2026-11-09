// Package config loads and validates CrowsNest's config.yaml: server
// settings, idle-shutdown policy, and the registry of game servers CrowsNest
// controls.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultAddr                 = ":5000"
	defaultSessionKeyFile       = "/app/.session_secret"
	defaultSettingsFile         = "/app/data/settings.json"
	defaultHistoryFile          = "/app/data/events.jsonl"
	defaultHistoryRetentionDays = 180
	defaultTZ                   = "UTC"
	defaultIdleMinutes          = 15
	defaultCheckIntervalSeconds = 60

	defaultNightShutdownStartHour            = 23
	defaultNightShutdownEndHour              = 5
	defaultNightShutdownCheckIntervalMinutes = 30
	defaultNightShutdownMinUptimeMinutes     = 30
)

var gameIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// Config is the root of config.yaml.
type Config struct {
	Server        ServerConfig         `yaml:"server"`
	IdleShutdown  *IdleShutdownConfig  `yaml:"idle_shutdown"`
	NightShutdown *NightShutdownConfig `yaml:"night_shutdown"`
	Notifications *NotificationsConfig `yaml:"notifications"`
	Auth          AuthConfig           `yaml:"auth"`
	UsersFile     string               `yaml:"users_file"`
	// ModulesDir is an optional directory of <id>/module.yaml game modules
	// (docs/modularization-plan.md). A module is used by the game in Games
	// with the same id. Empty means only the bundled modules.
	ModulesDir string       `yaml:"modules_dir"`
	Games      []GameConfig `yaml:"games"`
}

// ServerConfig holds top-level HTTP server settings.
type ServerConfig struct {
	Addr              string `yaml:"addr"`
	SessionSecretFile string `yaml:"session_secret_file"`
	TZ                string `yaml:"tz"`

	// SettingsFile is where options changed from the dashboard (idle
	// timeout, night window, max active games, auto-update) are saved. It
	// must be on a writable mount that survives container recreation, and
	// the mount should be a directory: the file is replaced atomically, which
	// a single-file bind mount does not allow. config.yaml supplies the
	// defaults until something is saved here. Default /app/data/settings.json.
	SettingsFile string `yaml:"settings_file"`

	// HistoryFile is the activity log (who started/stopped what, auto-stops,
	// joins and leaves) as JSON lines; keep it on the same persistent mount
	// as SettingsFile. Default /app/data/events.jsonl. Entries older than
	// HistoryRetentionDays (default 180) are pruned.
	// HostDiskPaths are mounted paths whose free space the dashboard shows
	// (one entry per filesystem). Default: /app/data and /data. Mount the
	// disk your game saves and images live on (read-only is fine) and list it
	// here to watch it.
	HostDiskPaths []string `yaml:"host_disk_paths"`

	HistoryFile          string `yaml:"history_file"`
	HistoryRetentionDays int    `yaml:"history_retention_days"`

	// TrustedProxies lists CIDRs of reverse proxies allowed to set
	// X-Forwarded-For; the client IP used for rate limiting is only taken
	// from that header when the request's RemoteAddr is in this list.
	// Empty (the default) means never trust it.
	TrustedProxies []string `yaml:"trusted_proxies"`

	// DockerHost, when set, points every docker/docker-compose CLI call at
	// this daemon instead of the local /var/run/docker.sock — e.g.
	// "tcp://docker-socket-proxy:2375" to run against a docker-socket-proxy
	// (see compose.yaml.example) instead of mounting the raw socket into
	// this container. Empty (the default) leaves the docker CLI's own
	// resolution in place (DOCKER_HOST env var, then the local socket).
	DockerHost string `yaml:"docker_host"`

	// SecureCookies marks the session cookie Secure and adds
	// Strict-Transport-Security to every response. Enable this when
	// CrowsNest sits behind a TLS-terminating reverse proxy; leave it off
	// for plain-HTTP LAN deployments, where a Secure cookie would never be
	// sent back by the browser at all.
	SecureCookies bool `yaml:"secure_cookies"`

	// MaxActiveGames caps how many game servers may run at once. Zero
	// (the default) means 1: starting a second game is refused and the UI
	// offers to switch instead. Overridden by the CROWSNEST_MAX_ACTIVE_GAMES
	// environment variable (e.g. from .env) when that is set.
	MaxActiveGames int `yaml:"max_active_games"`

	// AutoUpdate pulls the latest image for a game every time it is started
	// (`docker compose pull`), so restarts pick up new server versions.
	// Default false. Changeable at runtime from the dashboard.
	AutoUpdate bool `yaml:"auto_update"`
}

// AuthConfig chooses how people sign in.
type AuthConfig struct {
	// PasswordLogin enables username/password sign-in against users_file.
	// Nil (unset) means true. Set it false to make Google the only way in;
	// at least one sign-in method must stay enabled.
	PasswordLogin *bool `yaml:"password_login"`

	// Google enables "Sign in with Google" when set.
	Google *GoogleAuthConfig `yaml:"google"`
}

// PasswordLoginEnabled reports the effective password_login setting.
func (a AuthConfig) PasswordLoginEnabled() bool {
	return a.PasswordLogin == nil || *a.PasswordLogin
}

// GoogleAuthConfig configures Google sign-in. Like every other secret in
// this config, the values themselves live in environment variables (e.g.
// from .env), and these fields only name them.
type GoogleAuthConfig struct {
	// RedirectURL is the absolute callback URL, which must also be listed as
	// an authorized redirect URI on the Google OAuth client, e.g.
	// https://crowsnest.example.com/auth/google/callback. Its path must be
	// /auth/google/callback.
	RedirectURL string `yaml:"redirect_url"`

	// ClientIDEnv / ClientSecretEnv name the variables holding the OAuth
	// client's ID and secret. Defaults: CROWSNEST_GOOGLE_CLIENT_ID and
	// CROWSNEST_GOOGLE_CLIENT_SECRET.
	ClientIDEnv     string `yaml:"client_id_env"`
	ClientSecretEnv string `yaml:"client_secret_env"`

	// UsersEnv names the variable holding the allowlist: comma-separated
	// name=email pairs, e.g. "scott=scott@gmail.com,friend=pal@gmail.com".
	// Only these Google accounts may sign in, each as the CrowsNest
	// username before the '='. Default: CROWSNEST_GOOGLE_USERS.
	UsersEnv string `yaml:"users_env"`
}

// GoogleCallbackPath is the route auth.GoogleLogin serves the callback on
// (auth.GoogleCallbackPath); a test in cmd/crowsnest checks they agree.
const GoogleCallbackPath = "/auth/google/callback"

// MaxActiveGamesEnv names the environment variable that overrides
// server.max_active_games.
const MaxActiveGamesEnv = "CROWSNEST_MAX_ACTIVE_GAMES"

// IdleShutdownConfig controls the auto-stop-when-empty policy. A nil
// *IdleShutdownConfig on Config means "use defaults" (enabled); an explicit
// block with Enabled: false turns it off.
type IdleShutdownConfig struct {
	Enabled              bool `yaml:"enabled"`
	IdleMinutes          int  `yaml:"idle_minutes"`
	CheckIntervalSeconds int  `yaml:"check_interval_seconds"`
}

// NightShutdownConfig controls the time-window auto-stop policy: stop an
// online, empty game during a nightly window, independent of (and in
// addition to) idle-shutdown's continuous grace period. A nil
// *NightShutdownConfig on Config means "disabled" — unlike idle-shutdown,
// this isn't on by default: a preset curfew is a stronger, more surprising
// behavior than stopping only once a server has sat empty a while, and
// multi-game/multi-timezone friend groups don't share the original's
// single-user assumption that made an always-on curfew safe to default to.
type NightShutdownConfig struct {
	Enabled bool `yaml:"enabled"`
	// StartHour/EndHour are 0-23, local to Server.TZ. The window wraps
	// midnight when StartHour > EndHour (e.g. 23 -> 5 means 23:00-04:59).
	StartHour            int `yaml:"start_hour"`
	EndHour              int `yaml:"end_hour"`
	CheckIntervalMinutes int `yaml:"check_interval_minutes"`
	// MinUptimeMinutes protects a game started inside the window: it is not
	// stopped until it has been up this long. Defaults to 30.
	MinUptimeMinutes int `yaml:"min_uptime_minutes"`
}

// NotificationsConfig holds outbound-notification settings shared by
// idle-shutdown and night-shutdown.
type NotificationsConfig struct {
	// DiscordWebhookURLEnv names an environment variable holding the
	// Discord webhook URL, kept out of config.yaml itself like every other
	// secret in this config (rcon_password_env, rest_api_password_env).
	// Empty (the default) means notifications are disabled.
	DiscordWebhookURLEnv string `yaml:"discord_webhook_url_env"`

	// PlayerEvents posts a message when a player joins or leaves a game
	// (needs the webhook above). On by default; set false to silence it.
	PlayerEvents *bool `yaml:"player_events"`
}

// PlayerEventsEnabled reports whether join/leave messages are on.
func (n NotificationsConfig) PlayerEventsEnabled() bool {
	return n.PlayerEvents == nil || *n.PlayerEvents
}

// WindroseConfig holds Windrose-specific integration settings (Windrose+
// HTTP API / RCON).
type WindroseConfig struct {
	HTTPAPIURL      string `yaml:"http_api_url"`
	RCONPasswordEnv string `yaml:"rcon_password_env"`
}

// PalworldConfig holds Palworld-specific integration settings (the
// dedicated server's REST API).
type PalworldConfig struct {
	RESTAPIURL         string `yaml:"rest_api_url"`
	RESTAPIUser        string `yaml:"rest_api_user"`
	RESTAPIPasswordEnv string `yaml:"rest_api_password_env"`

	// RCONAddr (host:port, e.g. palworld:25575) enables the admin-only raw
	// console, once an admin switches it on in settings. Optional.
	// RCONPasswordEnv names the env var holding the RCON password; it
	// defaults to RESTAPIPasswordEnv because palworld-server-docker uses
	// ADMIN_PASSWORD for both.
	RCONAddr        string `yaml:"rcon_addr"`
	RCONPasswordEnv string `yaml:"rcon_password_env"`
}

// ConnectSecret is one labelled value on a game's card, read from the named
// environment variable.
type ConnectSecret struct {
	Label string `yaml:"label"`
	Env   string `yaml:"env"`
}

// GameConfig is one entry in the game registry.
type GameConfig struct {
	ID             string `yaml:"id"`
	DisplayName    string `yaml:"display_name"`
	ContainerName  string `yaml:"container_name"`
	ComposeFile    string `yaml:"compose_file"`
	ComposeProfile string `yaml:"compose_profile"`
	ComposeService string `yaml:"compose_service"`

	// ConnectAddress is an optional host:port shown on the game's card with
	// a copy button, so players know where to connect. ConnectNote is an
	// optional short free-text hint beside it. Both are display-only and
	// shown to every logged-in user: never put a password in either (a
	// server password belongs in your group chat, not the panel).
	ConnectAddress string `yaml:"connect_address"`
	ConnectNote    string `yaml:"connect_note"`

	// ConnectSecrets are labelled values shown under the address on the
	// card, each read from an environment variable at startup (so the value
	// stays in .env, never in config.yaml), e.g. the join password or an
	// invite code. Like the address they are shown to every logged-in user,
	// so list only what every signed-in player should see. Never list the
	// admin/REST password. An unset or empty variable is left out.
	ConnectSecrets []ConnectSecret `yaml:"connect_secrets"`

	// NightShutdown opts this game out of the global night-shutdown window
	// when explicitly set to false. Nil (the default) means "included,"
	// same as every other game, so long as night_shutdown.enabled is true.
	NightShutdown *bool `yaml:"night_shutdown,omitempty"`

	Windrose *WindroseConfig `yaml:"windrose,omitempty"`
	Palworld *PalworldConfig `yaml:"palworld,omitempty"`

	// Backup, when set, lets admins back the game up from the dashboard.
	Backup *BackupConfig `yaml:"backup,omitempty"`
}

// BackupConfig describes how to back one game up. Everything runs inside the
// game's container with `docker exec`, so it works with whatever the image
// ships (palworld-server-docker has a backup script; otherwise a tar
// command). The docker-socket-proxy needs EXEC=1 for this.
type BackupConfig struct {
	// Exec is the command and arguments run in the container, e.g.
	// ["/bin/sh", "-c", "backup"]. Required.
	Exec []string `yaml:"exec"`
	// ListDir is a directory inside the container holding the backup files,
	// listed newest first on the dashboard. Optional; the container needs GNU
	// find.
	ListDir string `yaml:"list_dir"`
	// BeforeStop also takes a backup each time the game is stopped on purpose
	// (manual, switch, idle or night), after the world is saved, so a fresh
	// backup always exists before an update-on-start pull.
	BeforeStop bool `yaml:"before_stop"`
}

// Load reads, defaults, and validates the config.yaml at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the config path is CROWSNEST_CONFIG or /app/config.yaml, set by the operator
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	cfg.applyDefaults()
	if v := os.Getenv(MaxActiveGamesEnv); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("config: %s=%q: not a whole number", MaxActiveGamesEnv, v)
		}
		cfg.Server.MaxActiveGames = n
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Addr == "" {
		c.Server.Addr = defaultAddr
	}
	if c.Server.SessionSecretFile == "" {
		c.Server.SessionSecretFile = defaultSessionKeyFile
	}
	if len(c.Server.HostDiskPaths) == 0 {
		c.Server.HostDiskPaths = []string{"/app/data", "/data"}
	}
	if c.Server.HistoryFile == "" {
		c.Server.HistoryFile = defaultHistoryFile
	}
	if c.Server.HistoryRetentionDays == 0 {
		c.Server.HistoryRetentionDays = defaultHistoryRetentionDays
	}
	if c.Server.SettingsFile == "" {
		c.Server.SettingsFile = defaultSettingsFile
	}
	if c.Server.TZ == "" {
		c.Server.TZ = defaultTZ
	}
	if c.Server.MaxActiveGames == 0 {
		c.Server.MaxActiveGames = 1
	}

	if c.IdleShutdown == nil {
		c.IdleShutdown = &IdleShutdownConfig{
			Enabled:              true,
			IdleMinutes:          defaultIdleMinutes,
			CheckIntervalSeconds: defaultCheckIntervalSeconds,
		}
	} else {
		if c.IdleShutdown.IdleMinutes == 0 {
			c.IdleShutdown.IdleMinutes = defaultIdleMinutes
		}
		if c.IdleShutdown.CheckIntervalSeconds == 0 {
			c.IdleShutdown.CheckIntervalSeconds = defaultCheckIntervalSeconds
		}
	}

	if c.NightShutdown == nil {
		// Disabled by default — see NightShutdownConfig's doc comment.
		c.NightShutdown = &NightShutdownConfig{Enabled: false}
	}
	if c.NightShutdown.StartHour == 0 && c.NightShutdown.EndHour == 0 {
		c.NightShutdown.StartHour = defaultNightShutdownStartHour
		c.NightShutdown.EndHour = defaultNightShutdownEndHour
	}
	if c.NightShutdown.MinUptimeMinutes == 0 {
		c.NightShutdown.MinUptimeMinutes = defaultNightShutdownMinUptimeMinutes
	}
	if c.NightShutdown.CheckIntervalMinutes == 0 {
		c.NightShutdown.CheckIntervalMinutes = defaultNightShutdownCheckIntervalMinutes
	}

	if c.Notifications == nil {
		c.Notifications = &NotificationsConfig{}
	}

	if g := c.Auth.Google; g != nil {
		if g.ClientIDEnv == "" {
			g.ClientIDEnv = "CROWSNEST_GOOGLE_CLIENT_ID"
		}
		if g.ClientSecretEnv == "" {
			g.ClientSecretEnv = "CROWSNEST_GOOGLE_CLIENT_SECRET" // #nosec G101 -- the name of an env var, not a secret
		}
		if g.UsersEnv == "" {
			g.UsersEnv = "CROWSNEST_GOOGLE_USERS"
		}
	}
}

// Location parses Server.TZ, which applyDefaults has already guaranteed is
// non-empty.
func (s ServerConfig) Location() (*time.Location, error) {
	return time.LoadLocation(s.TZ)
}

func (c *Config) validate() error {
	if c.UsersFile == "" {
		return fmt.Errorf("users_file is required")
	}
	if len(c.Games) == 0 {
		return fmt.Errorf("at least one game must be defined")
	}
	for i, cidr := range c.Server.TrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("server.trusted_proxies[%d] (%s): %w", i, cidr, err)
		}
	}
	if !c.Auth.PasswordLoginEnabled() && c.Auth.Google == nil {
		return fmt.Errorf("auth: password_login is false and auth.google is not set, so nobody could sign in")
	}
	if g := c.Auth.Google; g != nil {
		u, err := url.Parse(g.RedirectURL)
		switch {
		case g.RedirectURL == "":
			return fmt.Errorf("auth.google.redirect_url is required")
		case err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
			strings.ContainsAny(g.RedirectURL, "#%"):
			return fmt.Errorf("auth.google.redirect_url (%s): must be an absolute URL with no query or fragment", g.RedirectURL)
		case u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())):
			return fmt.Errorf("auth.google.redirect_url (%s): must be https (http only for localhost)", g.RedirectURL)
		case u.Path != GoogleCallbackPath:
			return fmt.Errorf("auth.google.redirect_url (%s): path must be %s", g.RedirectURL, GoogleCallbackPath)
		case u.Scheme == "https" && !c.Server.SecureCookies:
			return fmt.Errorf("auth.google.redirect_url is https, so server.secure_cookies must be true")
		}
	}
	for _, g := range c.Games {
		if b := g.Backup; b != nil {
			if len(b.Exec) == 0 || strings.TrimSpace(b.Exec[0]) == "" {
				return fmt.Errorf("games[%s].backup.exec: a command is required", g.ID)
			}
			if b.ListDir != "" && !strings.HasPrefix(b.ListDir, "/") {
				return fmt.Errorf("games[%s].backup.list_dir (%s): must be an absolute path inside the container", g.ID, b.ListDir)
			}
		}
		for j, s := range g.ConnectSecrets {
			if strings.TrimSpace(s.Label) == "" || strings.TrimSpace(s.Env) == "" {
				return fmt.Errorf("games[%s].connect_secrets[%d]: label and env are both required", g.ID, j)
			}
		}
	}
	if c.Server.MaxActiveGames < 1 {
		return fmt.Errorf("max active games (%d): must be >= 1", c.Server.MaxActiveGames)
	}
	if _, err := c.Server.Location(); err != nil {
		return fmt.Errorf("server.tz (%s): %w", c.Server.TZ, err)
	}

	if h := c.NightShutdown.StartHour; h < 0 || h > 23 {
		return fmt.Errorf("night_shutdown.start_hour (%d): must be 0-23", h)
	}
	if h := c.NightShutdown.EndHour; h < 0 || h > 23 {
		return fmt.Errorf("night_shutdown.end_hour (%d): must be 0-23", h)
	}
	if c.Server.HistoryRetentionDays < 0 {
		return fmt.Errorf("server.history_retention_days (%d): must be >= 0", c.Server.HistoryRetentionDays)
	}
	if c.NightShutdown.MinUptimeMinutes < 0 {
		return fmt.Errorf("night_shutdown.min_uptime_minutes (%d): must be >= 0", c.NightShutdown.MinUptimeMinutes)
	}
	if c.NightShutdown.CheckIntervalMinutes < 1 {
		return fmt.Errorf("night_shutdown.check_interval_minutes (%d): must be >= 1", c.NightShutdown.CheckIntervalMinutes)
	}

	ids := make(map[string]bool, len(c.Games))
	containers := make(map[string]string, len(c.Games))
	for i, g := range c.Games {
		if g.ID == "" {
			return fmt.Errorf("games[%d]: id is required", i)
		}
		if !gameIDPattern.MatchString(g.ID) {
			return fmt.Errorf("games[%d] (%s): id must match %s", i, g.ID, gameIDPattern.String())
		}
		if ids[g.ID] {
			return fmt.Errorf("games[%d]: duplicate id %q", i, g.ID)
		}
		ids[g.ID] = true

		if g.DisplayName == "" {
			return fmt.Errorf("games[%d] (%s): display_name is required", i, g.ID)
		}
		if g.ContainerName == "" {
			return fmt.Errorf("games[%d] (%s): container_name is required", i, g.ID)
		}
		if other, dup := containers[g.ContainerName]; dup {
			return fmt.Errorf("games[%d] (%s): container_name %q already used by game %q", i, g.ID, g.ContainerName, other)
		}
		containers[g.ContainerName] = g.ID

		if g.ComposeFile == "" {
			return fmt.Errorf("games[%d] (%s): compose_file is required", i, g.ID)
		}
		if g.ComposeProfile == "" {
			return fmt.Errorf("games[%d] (%s): compose_profile is required", i, g.ID)
		}
		if g.ComposeService == "" {
			return fmt.Errorf("games[%d] (%s): compose_service is required", i, g.ID)
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
