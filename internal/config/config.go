package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration.
type Config struct {
	Voyager   VoyagerConfig   `yaml:"voyager"`
	Tailscale TailscaleConfig `yaml:"tailscale"`
}

// VoyagerConfig contains all Voyager-related settings.
type VoyagerConfig struct {
	API     VoyagerAPIConfig `yaml:"api"`
	Project ProjectConfig    `yaml:"project"`
	Server  ServerConfig     `yaml:"server"`
}

// VoyagerAPIConfig contains Voyager API connection settings.
type VoyagerAPIConfig struct {
	BaseURL string `yaml:"base_url"`
	Token   string `yaml:"token"`
}

// ProjectConfig contains project settings.
type ProjectConfig struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// ServerConfig contains server provisioning settings.
type ServerConfig struct {
	Location        int    `yaml:"location"`
	Plan            int    `yaml:"plan"`
	OperatingSystem int    `yaml:"operatingsystem"`
	SSHKeys         []int  `yaml:"ssh_keys"`
	Fail2Ban        bool   `yaml:"fail2ban"`
	RunCmd          string `yaml:"runcmd"`
}

// TailscaleConfig contains optional Tailscale integration settings.
type TailscaleConfig struct {
	Enabled  bool               `yaml:"enabled"`
	ExitNode bool               `yaml:"exit_node"`
	API      TailscaleAPIConfig `yaml:"api"`
	Tags     []string           `yaml:"tags"`
}

// TailscaleAPIConfig contains Tailscale API connection settings.
type TailscaleAPIConfig struct {
	BaseURL      string   `yaml:"base_url"`
	ClientID     string   `yaml:"clientid"`
	ClientSecret string   `yaml:"clientsecret"`
	Tailnet      string   `yaml:"tailnet"`
	Scopes       []string `yaml:"scopes"`
}

// Load reads and parses configuration from a YAML file.
func Load(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// Validate checks whether required configuration values are present.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}

	if strings.TrimSpace(c.Voyager.API.BaseURL) == "" {
		return fmt.Errorf("voyager.api.base_url is required")
	}

	if strings.TrimSpace(c.Voyager.API.Token) == "" {
		return fmt.Errorf("voyager.api.token is required")
	}

	if strings.TrimSpace(c.Voyager.Project.Name) == "" {
		return fmt.Errorf("voyager.project.name is required")
	}

	if c.Tailscale.Enabled {
		if strings.TrimSpace(c.Tailscale.API.BaseURL) == "" {
			return fmt.Errorf("tailscale.api.base_url is required when tailscale.enabled is true")
		}

		if strings.TrimSpace(c.Tailscale.API.ClientID) == "" {
			return fmt.Errorf("tailscale.api.clientid is required when tailscale.enabled is true")
		}

		if strings.TrimSpace(c.Tailscale.API.ClientSecret) == "" {
			return fmt.Errorf("tailscale.api.clientsecret is required when tailscale.enabled is true")
		}

		if strings.TrimSpace(c.Tailscale.API.Tailnet) == "" {
			return fmt.Errorf("tailscale.api.tailnet is required when tailscale.enabled is true")
		}
	}

	return nil
}
