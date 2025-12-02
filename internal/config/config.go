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
	Policy          PolicyConfig              `yaml:"policy"`
	Intelligence    IntelligenceConfig        `yaml:"intelligence"`
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

type PIIEntitiesConfig struct {
	Email      bool `yaml:"email"`
	Phone      bool `yaml:"phone"`
	CreditCard bool `yaml:"credit_card"`
	IBAN       bool `yaml:"iban"`
	Tokens     bool `yaml:"tokens"`
}

type PolicyConfig struct {
	BannedWords     string   `yaml:"banned_words"`      // action: block | log | ignore | redact
	BannedWordsList []string `yaml:"banned_words_list"` // actual banned terms

	PII         string            `yaml:"pii"`          // action: block | log | ignore | redact
	PIIEntities PIIEntitiesConfig `yaml:"pii_entities"` // PII entity toggles

	Injection       string `yaml:"injection"`
	PromptInjection string `yaml:"prompt_injection"`
	Jailbreak       string `yaml:"jailbreak"`
	Toxicity        string `yaml:"toxicity"`
}

type IntelligenceConfig struct {
    // Enabled controls whether Straja runs the intelligence / policy engine
    // at all. When false, Straja becomes a pure routing + activation proxy.
    Enabled bool `yaml:"enabled"`

    // These fields are placeholders for Phase 2 and later
    // (bundle download, license, updates).
    BundleCacheDir      string `yaml:"bundle_cache_dir"`
    LicenseKeyEnv       string `yaml:"license_key_env"`
    AutoUpdate          bool   `yaml:"auto_update"`
    UpdateCheckInterval string `yaml:"update_check_interval"`
}

// IsZero reports whether the struct was effectively omitted from the YAML.
// This mirrors the PIIEntities pattern so we can apply sensible defaults.
func (c IntelligenceConfig) IsZero() bool {
    return !c.Enabled &&
        c.BundleCacheDir == "" &&
        c.LicenseKeyEnv == "" &&
        !c.AutoUpdate &&
        c.UpdateCheckInterval == ""
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
        Policy: PolicyConfig{
            BannedWords:     "block",
            PII:             "block",
            Injection:       "block",
            PromptInjection: "block",
            Jailbreak:       "block",
            Toxicity:        "log",
        },
        Intelligence: IntelligenceConfig{
            Enabled:             true,
            BundleCacheDir:      "~/.straja/bundles",
            LicenseKeyEnv:       "STRAJA_LICENSE_KEY",
            AutoUpdate:          true,
            UpdateCheckInterval: "6h",
        },
    }
}

func (c PIIEntitiesConfig) IsZero() bool {
	return !c.Email && !c.Phone && !c.CreditCard && !c.IBAN && !c.Tokens
}

func applyDefaults(cfg *Config) {
	// Default server address
	if cfg.Server.Addr == "" {
		cfg.Server.Addr = ":8080"
	}

	// Default provider logic: if only one provider exists, use it
	if cfg.DefaultProvider == "" && len(cfg.Providers) == 1 {
		for name := range cfg.Providers {
			cfg.DefaultProvider = name
			break
		}
	}

	// Logging defaults
	if cfg.Logging.ActivationLevel == "" {
		cfg.Logging.ActivationLevel = "metadata"
	}

	// Policy action defaults
	if cfg.Policy.BannedWords == "" {
		cfg.Policy.BannedWords = "block"
	}
	if cfg.Policy.PII == "" {
		cfg.Policy.PII = "block"
	}
	if cfg.Policy.Injection == "" {
		cfg.Policy.Injection = "block"
	}
	if cfg.Policy.PromptInjection == "" {
		cfg.Policy.PromptInjection = "block"
	}
	if cfg.Policy.Jailbreak == "" {
		cfg.Policy.Jailbreak = "block"
	}
	if cfg.Policy.Toxicity == "" {
		cfg.Policy.Toxicity = "log"
	}

	// PII ENTITIES DEFAULTS:
	// If user omitted pii_entities entirely (zero struct), default to all true.
	if cfg.Policy.PIIEntities.IsZero() {
		cfg.Policy.PIIEntities = PIIEntitiesConfig{
			Email:      true,
			Phone:      true,
			CreditCard: true,
			IBAN:       true,
			Tokens:     true,
		}
	}

	// Intelligence defaults
    if cfg.Intelligence.IsZero() {
        cfg.Intelligence = IntelligenceConfig{
            Enabled:             true,
            BundleCacheDir:      "~/.straja/bundles",
            LicenseKeyEnv:       "STRAJA_LICENSE_KEY",
            AutoUpdate:          true,
            UpdateCheckInterval: "6h",
        }
    } else {
        if cfg.Intelligence.BundleCacheDir == "" {
            cfg.Intelligence.BundleCacheDir = "~/.straja/bundles"
        }
        if cfg.Intelligence.LicenseKeyEnv == "" {
            cfg.Intelligence.LicenseKeyEnv = "STRAJA_LICENSE_KEY"
        }
        if cfg.Intelligence.UpdateCheckInterval == "" {
            cfg.Intelligence.UpdateCheckInterval = "6h"
        }
    }
}
