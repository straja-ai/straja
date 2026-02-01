package responseguard

import (
	"strings"

	"github.com/straja-ai/straja/internal/config"
)

type Config struct {
	Enabled    bool
	Mode       string
	Categories CategoryConfig
}

type CategoryConfig struct {
	DataExfilInstruction           string
	UnsafeActionInstruction        string
	PrivilegeEscalationInstruction string
}

func DefaultConfig() Config {
	return Config{
		Enabled: true,
		Mode:    "warn",
	}
}

func FromConfig(cfg config.ResponseGuardConfig) Config {
	out := Config{
		Enabled: cfg.Enabled,
		Mode:    cfg.Mode,
		Categories: CategoryConfig{
			DataExfilInstruction:           cfg.Categories.DataExfilInstruction,
			UnsafeActionInstruction:        cfg.Categories.UnsafeActionInstruction,
			PrivilegeEscalationInstruction: cfg.Categories.PrivilegeEscalationInstruction,
		},
	}
	return applyDefaults(out)
}

func applyDefaults(cfg Config) Config {
	if !cfg.Enabled {
		return cfg
	}
	if strings.TrimSpace(cfg.Mode) == "" {
		cfg.Mode = "warn"
	}
	return cfg
}

func (c Config) actionForCategory(category string) string {
	override := ""
	switch category {
	case CategoryDataExfilInstruction:
		override = c.Categories.DataExfilInstruction
	case CategoryUnsafeActionInstruction:
		override = c.Categories.UnsafeActionInstruction
	case CategoryPrivilegeEscalationInstruction:
		override = c.Categories.PrivilegeEscalationInstruction
	}
	if strings.TrimSpace(override) != "" {
		return normalizeAction(override)
	}
	return normalizeAction(c.Mode)
}

func normalizeAction(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "warn":
		return "warn"
	case "ignore":
		return "ignore"
	default:
		return "warn"
	}
}
