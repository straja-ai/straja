package config

import (
	"strings"
	"testing"
)

func TestValidateFailures(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		want string
	}{
		{
			name: "missing server addr",
			cfg: &Config{
				Server: ServerConfig{Addr: ""},
			},
			want: "server.addr",
		},
		{
			name: "no providers",
			cfg: &Config{
				Server: ServerConfig{Addr: ":8080"},
			},
			want: "provider",
		},
		{
			name: "missing default provider",
			cfg: &Config{
				Server:          ServerConfig{Addr: ":8080"},
				Providers:       map[string]ProviderConfig{"p1": {Type: "openai", APIKeyEnv: "KEY", BaseURL: "https://example.com"}},
				DefaultProvider: "",
			},
			want: "default_provider",
		},
		{
			name: "project references unknown provider",
			cfg: &Config{
				Server:          ServerConfig{Addr: ":8080"},
				Providers:       map[string]ProviderConfig{"p1": {Type: "openai", APIKeyEnv: "KEY", BaseURL: "https://example.com"}},
				DefaultProvider: "p1",
				Projects:        []ProjectConfig{{ID: "proj", Provider: "missing", APIKeys: []string{"k"}}},
				Security:        defaultSecurityConfig(),
			},
			want: "unknown provider",
		},
		{
			name: "missing api keys when security enabled",
			cfg: &Config{
				Server:          ServerConfig{Addr: ":8080"},
				Providers:       map[string]ProviderConfig{"p1": {Type: "openai", APIKeyEnv: "KEY", BaseURL: "https://example.com"}},
				DefaultProvider: "p1",
				Projects:        []ProjectConfig{{ID: "proj", Provider: "p1"}},
				Security:        defaultSecurityConfig(),
			},
			want: "api_keys",
		},
		{
			name: "invalid provider url",
			cfg: &Config{
				Server:          ServerConfig{Addr: ":8080"},
				Providers:       map[string]ProviderConfig{"p1": {Type: "openai", APIKeyEnv: "KEY", BaseURL: "::://bad"}},
				DefaultProvider: "p1",
				Projects:        []ProjectConfig{{ID: "proj", Provider: "p1", APIKeys: []string{"k"}}},
				Security:        defaultSecurityConfig(),
			},
			want: "base_url",
		},
		{
			name: "provider url blocked private",
			cfg: &Config{
				Server:          ServerConfig{Addr: ":8080"},
				Providers:       map[string]ProviderConfig{"p1": {Type: "openai", APIKeyEnv: "KEY", BaseURL: "http://127.0.0.1:8081"}},
				DefaultProvider: "p1",
				Projects:        []ProjectConfig{{ID: "proj", Provider: "p1", APIKeys: []string{"k"}}},
				Security:        defaultSecurityConfig(),
			},
			want: "SSRF",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(tc.cfg); err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			} else if !contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidateOK(t *testing.T) {
	cfg := &Config{
		Server:          ServerConfig{Addr: ":8080"},
		Providers:       map[string]ProviderConfig{"p1": {Type: "openai", APIKeyEnv: "KEY", BaseURL: "https://example.com"}},
		DefaultProvider: "p1",
		Projects:        []ProjectConfig{{ID: "proj", Provider: "p1", APIKeys: []string{"k"}}},
		Security:        defaultSecurityConfig(),
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}

	loopbackOK := &Config{
		Server:          ServerConfig{Addr: ":8080"},
		Providers:       map[string]ProviderConfig{"mock": {Type: "mock", APIKeyEnv: "KEY", BaseURL: "http://127.0.0.1:18080", AllowPrivateNetworks: true}},
		DefaultProvider: "mock",
		Projects:        []ProjectConfig{{ID: "proj", Provider: "mock", APIKeys: []string{"k"}}},
		Security:        defaultSecurityConfig(),
	}
	if err := Validate(loopbackOK); err != nil {
		t.Fatalf("expected loopback allowed when allow_private_networks=true, got %v", err)
	}
}

func contains(s, sub string) bool {
	return s != "" && sub != "" && strings.Contains(s, sub)
}
