// Package config loads and validates CrowsNest's config.yaml: server
// settings, idle-shutdown policy, and the registry of game servers CrowsNest
// controls.
package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultAddr                 = ":5000"
	defaultSessionSecretFile    = "/app/.session_secret"
	defaultTZ                   = "UTC"
	defaultIdleMinutes          = 15
	defaultCheckIntervalSeconds = 60

	defaultNightShutdownStartHour            = 23
	defaultNightShutdownEndHour              = 5
	defaultNightShutdownCheckIntervalMinutes = 30
)

var gameIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// Config is the root of config.yaml.
type Config struct {
	Server        ServerConfig         `yaml:"server"`
	IdleShutdown  *IdleShutdownConfig  `yaml:"idle_shutdown"`
	NightShutdown *NightShutdownConfig `yaml:"night_shutdown"`
	Notifications *NotificationsConfig `yaml:"notifications"`
	UsersFile     string               `yaml:"users_file"`
	Games         []GameConfig         `yaml:"games"`
}

// ServerConfig holds top-level HTTP server settings.
type ServerConfig struct {
	Addr              string `yaml:"addr"`
	SessionSecretFile string `yaml:"session_secret_file"`
	TZ                string `yaml:"tz"`

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
}

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
}

// NotificationsConfig holds outbound-notification settings shared by
// idle-shutdown and night-shutdown.
type NotificationsConfig struct {
	// DiscordWebhookURLEnv names an environment variable holding the
	// Discord webhook URL, kept out of config.yaml itself like every other
	// secret in this config (rcon_password_env, rest_api_password_env).
	// Empty (the default) means notifications are disabled.
	DiscordWebhookURLEnv string `yaml:"discord_webhook_url_env"`
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
}

// GameConfig is one entry in the game registry.
type GameConfig struct {
	ID             string `yaml:"id"`
	DisplayName    string `yaml:"display_name"`
	ContainerName  string `yaml:"container_name"`
	ComposeFile    string `yaml:"compose_file"`
	ComposeProfile string `yaml:"compose_profile"`
	ComposeService string `yaml:"compose_service"`
	EnvFile        string `yaml:"env_file"`

	// NightShutdown opts this game out of the global night-shutdown window
	// when explicitly set to false. Nil (the default) means "included,"
	// same as every other game, so long as night_shutdown.enabled is true.
	NightShutdown *bool `yaml:"night_shutdown,omitempty"`

	Windrose *WindroseConfig `yaml:"windrose,omitempty"`
	Palworld *PalworldConfig `yaml:"palworld,omitempty"`
}

// Load reads, defaults, and validates the config.yaml at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	cfg.applyDefaults()
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
		c.Server.SessionSecretFile = defaultSessionSecretFile
	}
	if c.Server.TZ == "" {
		c.Server.TZ = defaultTZ
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
	if c.NightShutdown.CheckIntervalMinutes == 0 {
		c.NightShutdown.CheckIntervalMinutes = defaultNightShutdownCheckIntervalMinutes
	}

	if c.Notifications == nil {
		c.Notifications = &NotificationsConfig{}
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
	if _, err := c.Server.Location(); err != nil {
		return fmt.Errorf("server.tz (%s): %w", c.Server.TZ, err)
	}

	if h := c.NightShutdown.StartHour; h < 0 || h > 23 {
		return fmt.Errorf("night_shutdown.start_hour (%d): must be 0-23", h)
	}
	if h := c.NightShutdown.EndHour; h < 0 || h > 23 {
		return fmt.Errorf("night_shutdown.end_hour (%d): must be 0-23", h)
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
