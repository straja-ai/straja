package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	Security        SecurityConfig            `yaml:"security"`
	Intel           IntelConfig               `yaml:"intel"`
}

// IntelConfig holds ML bundle + license settings.
type IntelConfig struct {
	StrajaGuardV1 StrajaGuardV1Config `yaml:"strajaguard_v1"`
}

// StrajaGuardV1Config controls StrajaGuard bundle fetching + validation.
type StrajaGuardV1Config struct {
	Enabled               bool   `yaml:"enabled"`
	LicenseServerBaseURL  string `yaml:"license_server_base_url"`
	LicenseKey            string `yaml:"license_key"`
	RequestTimeoutSeconds int    `yaml:"request_timeout_seconds"`
	IntelDir              string `yaml:"intel_dir"`
	VersionFile           string `yaml:"version_file"`
	AllowRegexOnly        bool   `yaml:"allow_regex_only"`
	UpdateOnStart         bool   `yaml:"update_on_start"`
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

	// LicenseKey is the offline-verifiable license string (e.g. "STRAJA-FREE-...")
	LicenseKey string `yaml:"license_key"`

	// LicenseServerURL is an optional online validation endpoint.
	LicenseServerURL string `yaml:"license_server_url"`

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
		c.LicenseKey == "" &&
		c.LicenseServerURL == "" &&
		!c.AutoUpdate &&
		c.UpdateCheckInterval == ""
}

func (c SecurityConfig) isZero() bool {
	return c == (SecurityConfig{})
}

func defaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		Enabled:   true,
		BundleDir: "./intel/strajaguard_v1",
		SeqLen:    256,
		PromptInj: SecurityCategoryConfig{
			RegexEnabled:     true,
			MLEnabled:        true,
			MLWarnThreshold:  0.60,
			MLBlockThreshold: 0.80,
			ActionOnBlock:    "block",
		},
		Jailbreak: SecurityCategoryConfig{
			RegexEnabled:     true,
			MLEnabled:        true,
			MLWarnThreshold:  0.60,
			MLBlockThreshold: 0.80,
			ActionOnBlock:    "block",
		},
		DataExfil: SecurityCategoryConfig{
			RegexEnabled:     true,
			MLEnabled:        true,
			MLWarnThreshold:  0.55,
			MLBlockThreshold: 0.75,
			ActionOnBlock:    "block",
		},
		PII: PIICategoryConfig{
			RegexEnabled:     true,
			MLEnabled:        true,
			MLWarnThreshold:  0.50,
			ActionOnRegexHit: "redact",
			ActionOnMLOnly:   "log",
		},
		Secrets: SecretsCategoryConfig{
			RegexEnabled:     true,
			MLEnabled:        true,
			MLWarnThreshold:  0.50,
			MLBlockThreshold: 0.85,
			ActionOnRegexHit: "block_and_redact",
			ActionOnMLOnly:   "log",
		},
	}
}

func (c *SecurityConfig) applyDefaults() {
	def := defaultSecurityConfig()

	if c.BundleDir == "" {
		c.BundleDir = def.BundleDir
	}
	if c.SeqLen == 0 {
		c.SeqLen = def.SeqLen
	}
	if c.PromptInj == (SecurityCategoryConfig{}) {
		c.PromptInj = def.PromptInj
	} else {
		applyCategoryDefaults(&c.PromptInj, def.PromptInj)
	}
	if c.Jailbreak == (SecurityCategoryConfig{}) {
		c.Jailbreak = def.Jailbreak
	} else {
		applyCategoryDefaults(&c.Jailbreak, def.Jailbreak)
	}
	if c.DataExfil == (SecurityCategoryConfig{}) {
		c.DataExfil = def.DataExfil
	} else {
		applyCategoryDefaults(&c.DataExfil, def.DataExfil)
	}
	if c.PII == (PIICategoryConfig{}) {
		c.PII = def.PII
	} else {
		if c.PII.MLWarnThreshold == 0 {
			c.PII.MLWarnThreshold = def.PII.MLWarnThreshold
		}
		if c.PII.ActionOnRegexHit == "" {
			c.PII.ActionOnRegexHit = def.PII.ActionOnRegexHit
		}
		if c.PII.ActionOnMLOnly == "" {
			c.PII.ActionOnMLOnly = def.PII.ActionOnMLOnly
		}
	}
	if c.Secrets == (SecretsCategoryConfig{}) {
		c.Secrets = def.Secrets
	} else {
		if c.Secrets.MLWarnThreshold == 0 {
			c.Secrets.MLWarnThreshold = def.Secrets.MLWarnThreshold
		}
		if c.Secrets.MLBlockThreshold == 0 {
			c.Secrets.MLBlockThreshold = def.Secrets.MLBlockThreshold
		}
		if c.Secrets.ActionOnRegexHit == "" {
			c.Secrets.ActionOnRegexHit = def.Secrets.ActionOnRegexHit
		}
		if c.Secrets.ActionOnMLOnly == "" {
			c.Secrets.ActionOnMLOnly = def.Secrets.ActionOnMLOnly
		}
	}
}

func applyCategoryDefaults(cfg *SecurityCategoryConfig, def SecurityCategoryConfig) {
	if cfg.MLWarnThreshold == 0 {
		cfg.MLWarnThreshold = def.MLWarnThreshold
	}
	if cfg.MLBlockThreshold == 0 {
		cfg.MLBlockThreshold = def.MLBlockThreshold
	}
	if cfg.ActionOnBlock == "" {
		cfg.ActionOnBlock = def.ActionOnBlock
	}
	if cfg.ActionOnRegexHit == "" {
		cfg.ActionOnRegexHit = def.ActionOnRegexHit
	}
}

// SecurityConfig configures the ML + regex security layers.
type SecurityConfig struct {
	Enabled   bool                   `yaml:"enabled"`
	BundleDir string                 `yaml:"bundle_dir"`
	SeqLen    int                    `yaml:"seq_len"`
	PromptInj SecurityCategoryConfig `yaml:"prompt_injection"`
	Jailbreak SecurityCategoryConfig `yaml:"jailbreak"`
	DataExfil SecurityCategoryConfig `yaml:"data_exfil"`
	PII       PIICategoryConfig      `yaml:"pii"`
	Secrets   SecretsCategoryConfig  `yaml:"secrets"`
}

// SecurityCategoryConfig is used for threat-style categories (prompt injection, jailbreak, exfil).
type SecurityCategoryConfig struct {
	RegexEnabled     bool    `yaml:"regex_enabled"`
	MLEnabled        bool    `yaml:"ml_enabled"`
	MLWarnThreshold  float32 `yaml:"ml_warn_threshold"`
	MLBlockThreshold float32 `yaml:"ml_block_threshold"`
	ActionOnBlock    string  `yaml:"action_on_block"`
	ActionOnRegexHit string  `yaml:"action_on_regex_hit,omitempty"`
}

// PIICategoryConfig controls how PII signals are handled.
type PIICategoryConfig struct {
	RegexEnabled     bool    `yaml:"regex_enabled"`
	MLEnabled        bool    `yaml:"ml_enabled"`
	MLWarnThreshold  float32 `yaml:"ml_warn_threshold"`
	ActionOnRegexHit string  `yaml:"action_on_regex_hit"`
	ActionOnMLOnly   string  `yaml:"action_on_ml_only"`
}

// SecretsCategoryConfig controls secret-related signals.
type SecretsCategoryConfig struct {
	RegexEnabled     bool    `yaml:"regex_enabled"`
	MLEnabled        bool    `yaml:"ml_enabled"`
	MLWarnThreshold  float32 `yaml:"ml_warn_threshold"`
	MLBlockThreshold float32 `yaml:"ml_block_threshold"`
	ActionOnRegexHit string  `yaml:"action_on_regex_hit"`
	ActionOnMLOnly   string  `yaml:"action_on_ml_only"`
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

	cfg := defaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	applyDefaults(cfg)

	return cfg, nil
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
		Intel:    defaultIntelConfig(),
		Security: defaultSecurityConfig(),
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

	// Security defaults
	if cfg.Security.isZero() {
		cfg.Security = defaultSecurityConfig()
	} else {
		cfg.Security.applyDefaults()
	}

	// Intel defaults (bundle + license flow)
	if cfg.Intel == (IntelConfig{}) {
		cfg.Intel = defaultIntelConfig()
	} else {
		cfg.Intel.applyDefaults()
	}

	// Align bundle dir with intel dir if user omitted bundle_dir.
	if cfg.Security.BundleDir == "" && cfg.Intel.StrajaGuardV1.IntelDir != "" {
		cfg.Security.BundleDir = filepath.Join(cfg.Intel.StrajaGuardV1.IntelDir, "strajaguard_v1")
	}
}

func defaultIntelConfig() IntelConfig {
	return IntelConfig{
		StrajaGuardV1: StrajaGuardV1Config{
			Enabled:               true,
			LicenseServerBaseURL:  "https://straja.ai",
			RequestTimeoutSeconds: 60,
			IntelDir:              "./intel",
			VersionFile:           "version",
			AllowRegexOnly:        false,
			UpdateOnStart:         true,
		},
	}
}

func (c *IntelConfig) applyDefaults() {
	def := defaultIntelConfig()

	if c.StrajaGuardV1 == (StrajaGuardV1Config{}) {
		c.StrajaGuardV1 = def.StrajaGuardV1
		return
	}

	if c.StrajaGuardV1.LicenseServerBaseURL == "" {
		c.StrajaGuardV1.LicenseServerBaseURL = def.StrajaGuardV1.LicenseServerBaseURL
	}
	if c.StrajaGuardV1.RequestTimeoutSeconds == 0 {
		c.StrajaGuardV1.RequestTimeoutSeconds = def.StrajaGuardV1.RequestTimeoutSeconds
	}
	if c.StrajaGuardV1.IntelDir == "" {
		c.StrajaGuardV1.IntelDir = def.StrajaGuardV1.IntelDir
	}
	if c.StrajaGuardV1.VersionFile == "" {
		c.StrajaGuardV1.VersionFile = def.StrajaGuardV1.VersionFile
	}
	if envVal, ok := envBool("STRAJA_ALLOW_REGEX_ONLY"); ok {
		c.StrajaGuardV1.AllowRegexOnly = envVal
	}
	if envVal, ok := envBool("STRAJA_UPDATE_ON_START"); ok {
		c.StrajaGuardV1.UpdateOnStart = envVal
	}
}

func envBool(name string) (bool, bool) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return false, false
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, false
	}
	return v, true
}
