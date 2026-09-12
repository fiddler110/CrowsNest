// Package config loads and validates CrowsNest's config.yaml: server
// settings, idle-shutdown policy, and the registry of game servers CrowsNest
// controls.
package config

import (
	"fmt"
	"net"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

const (
	defaultAddr                 = ":5000"
	defaultSessionSecretFile    = "/app/.session_secret"
	defaultTZ                   = "UTC"
	defaultIdleMinutes          = 15
	defaultCheckIntervalSeconds = 60
)

var gameIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// Config is the root of config.yaml.
type Config struct {
	Server       ServerConfig        `yaml:"server"`
	IdleShutdown *IdleShutdownConfig `yaml:"idle_shutdown"`
	UsersFile    string              `yaml:"users_file"`
	Games        []GameConfig        `yaml:"games"`
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
}

// IdleShutdownConfig controls the auto-stop-when-empty policy. A nil
// *IdleShutdownConfig on Config means "use defaults" (enabled); an explicit
// block with Enabled: false turns it off.
type IdleShutdownConfig struct {
	Enabled              bool `yaml:"enabled"`
	IdleMinutes          int  `yaml:"idle_minutes"`
	CheckIntervalSeconds int  `yaml:"check_interval_seconds"`
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
		return
	}
	if c.IdleShutdown.IdleMinutes == 0 {
		c.IdleShutdown.IdleMinutes = defaultIdleMinutes
	}
	if c.IdleShutdown.CheckIntervalSeconds == 0 {
		c.IdleShutdown.CheckIntervalSeconds = defaultCheckIntervalSeconds
	}
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
