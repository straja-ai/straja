package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds Straja configuration.
type Config struct {
	Server          ServerConfig              `yaml:"server"`
	Providers       map[string]ProviderConfig `yaml:"providers"`
	DefaultProvider string                    `yaml:"default_provider"`
	Projects        []ProjectConfig           `yaml:"projects"`
	Logging         LoggingConfig             `yaml:"logging"`
}

type ServerConfig struct {
	Addr string `yaml:"addr"` // HTTP listen address, e.g. ":8080"
}

type ProviderConfig struct {
	Type      string `yaml:"type"`        // e.g. "openai"
	BaseURL   string `yaml:"base_url"`    // e.g. "https://api.openai.com/v1"
	APIKeyEnv string `yaml:"api_key_env"` // e.g. "OPENAI_API_KEY"
}

type ProjectConfig struct {
	ID       string   `yaml:"id"`
	Provider string   `yaml:"provider"` // provider name from Providers map
	APIKeys  []string `yaml:"api_keys"`
}

type LoggingConfig struct {
	ActivationLevel string `yaml:"activation_level"`
}

// Load reads configuration from a YAML file.
// If the file doesn't exist, it returns a default config and no error.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// If file doesn't exist, return default config
		if os.IsNotExist(err) {
			return defaultConfig(), nil
		}
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	applyDefaults(&cfg)

	return &cfg, nil
}

func defaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Addr: ":8080",
		},
		Providers:       map[string]ProviderConfig{},
		DefaultProvider: "",
		Projects:        []ProjectConfig{},
		Logging: LoggingConfig{
			ActivationLevel: "metadata",
		},
	}
}

func applyDefaults(cfg *Config) {
	if cfg.Server.Addr == "" {
		cfg.Server.Addr = ":8080"
	}

	// If no default provider is set but there's exactly one provider,
	// use that as default.
	if cfg.DefaultProvider == "" && len(cfg.Providers) == 1 {
		for name := range cfg.Providers {
			cfg.DefaultProvider = name
			break
		}
	}

	if cfg.Logging.ActivationLevel == "" {
		cfg.Logging.ActivationLevel = "metadata"
	}
}
