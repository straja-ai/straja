package server

import (
	"os"
	"testing"

	"github.com/straja-ai/straja-gateway/internal/config"
)

func TestBuildProviderRegistry_EnvAndConfigFallback(t *testing.T) {
	cfg := &config.Config{
		Server:          config.ServerConfig{Addr: ":8080"},
		DefaultProvider: "openai",
		Providers: map[string]config.ProviderConfig{
			"openai": {
				Type:      "openai",
				BaseURL:   "https://api.openai.com/v1",
				APIKeyEnv: "TEST_OPENAI_KEY",
				APIKey:    "",
			},
		},
		Projects: []config.ProjectConfig{
			{ID: "p1", Provider: "openai", APIKeys: []string{"k"}},
		},
	}
	os.Setenv("TEST_OPENAI_KEY", "env-key")
	if _, err := buildProviderRegistry(cfg); err != nil {
		t.Fatalf("expected env key to work, got %v", err)
	}

	os.Unsetenv("TEST_OPENAI_KEY")
	cfg.Providers["openai"] = config.ProviderConfig{
		Type:      "openai",
		BaseURL:   "https://api.openai.com/v1",
		APIKeyEnv: "TEST_OPENAI_KEY",
		APIKey:    "config-key",
	}
	if _, err := buildProviderRegistry(cfg); err != nil {
		t.Fatalf("expected config api_key to work when env empty, got %v", err)
	}

	cfg.Providers["openai"] = config.ProviderConfig{
		Type:      "openai",
		BaseURL:   "https://api.openai.com/v1",
		APIKeyEnv: "TEST_OPENAI_KEY",
		APIKey:    "",
	}
	if _, err := buildProviderRegistry(cfg); err == nil {
		t.Fatalf("expected error when both env and api_key are empty")
	}
}

func TestBuildProviderRegistry_ClaudeEnvAndConfigFallback(t *testing.T) {
	cfg := &config.Config{
		Server:          config.ServerConfig{Addr: ":8080"},
		DefaultProvider: "claude",
		Providers: map[string]config.ProviderConfig{
			"claude": {
				Type:      "claude",
				BaseURL:   "https://api.anthropic.com/v1",
				APIKeyEnv: "TEST_CLAUDE_KEY",
				APIKey:    "",
			},
		},
		Projects: []config.ProjectConfig{
			{ID: "p1", Provider: "claude", APIKeys: []string{"k"}},
		},
	}
	os.Setenv("TEST_CLAUDE_KEY", "env-key")
	if _, err := buildProviderRegistry(cfg); err != nil {
		t.Fatalf("expected env key to work, got %v", err)
	}

	os.Unsetenv("TEST_CLAUDE_KEY")
	cfg.Providers["claude"] = config.ProviderConfig{
		Type:      "claude",
		BaseURL:   "https://api.anthropic.com/v1",
		APIKeyEnv: "TEST_CLAUDE_KEY",
		APIKey:    "config-key",
	}
	if _, err := buildProviderRegistry(cfg); err != nil {
		t.Fatalf("expected config api_key to work when env empty, got %v", err)
	}

	cfg.Providers["claude"] = config.ProviderConfig{
		Type:      "claude",
		BaseURL:   "https://api.anthropic.com/v1",
		APIKeyEnv: "TEST_CLAUDE_KEY",
		APIKey:    "",
	}
	if _, err := buildProviderRegistry(cfg); err == nil {
		t.Fatalf("expected error when both env and api_key are empty")
	}
}
