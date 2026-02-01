package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Validate checks the loaded config for required fields and safe values.
func Validate(cfg *Config) error {
	if cfg == nil {
		return errors.New("config is nil")
	}

	if strings.TrimSpace(cfg.Server.Addr) == "" {
		return errors.New("server.addr must be set")
	}

	if len(cfg.Providers) == 0 {
		return errors.New("at least one provider must be configured")
	}
	if strings.TrimSpace(cfg.DefaultProvider) == "" {
		return errors.New("default_provider must be set")
	}
	if _, ok := cfg.Providers[cfg.DefaultProvider]; !ok {
		return fmt.Errorf("default_provider %q not found in providers", cfg.DefaultProvider)
	}

	for name, p := range cfg.Providers {
		if err := validateProviderConfig(name, p); err != nil {
			return err
		}
	}

	if len(cfg.Projects) == 0 {
		return errors.New("at least one project must be configured")
	}

	for _, p := range cfg.Projects {
		if strings.TrimSpace(p.ID) == "" {
			return errors.New("project id must be set")
		}
		providerName := p.Provider
		if providerName == "" {
			providerName = cfg.DefaultProvider
		}
		if _, ok := cfg.Providers[providerName]; !ok {
			return fmt.Errorf("project %q references unknown provider %q", p.ID, providerName)
		}
		if cfg.Security.Enabled && len(p.APIKeys) == 0 {
			return fmt.Errorf("project %q must define at least one api_keys entry", p.ID)
		}
	}

	if err := validateActivationConfig(cfg.Activation); err != nil {
		return err
	}

	if err := validateTelemetryConfig(cfg.Telemetry); err != nil {
		return err
	}

	if err := validateToolGateConfig(cfg.ToolGate); err != nil {
		return err
	}

	if err := validateResponseGuardConfig(cfg.ResponseGuard); err != nil {
		return err
	}

	return nil
}

func validateProviderConfig(name string, p ProviderConfig) error {
	if strings.TrimSpace(p.Type) == "" {
		return fmt.Errorf("provider %q missing type", name)
	}
	if strings.EqualFold(p.Type, "openai") {
		if strings.TrimSpace(p.APIKeyEnv) == "" && strings.TrimSpace(p.APIKey) == "" {
			return fmt.Errorf("provider %q missing api key (env or api_key)", name)
		}
	}
	if p.BaseURL != "" {
		u, err := url.Parse(p.BaseURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("provider %q has invalid base_url", name)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("provider %q base_url must be http or https", name)
		}
		if err := blockPrivateHost(u.Host, p.AllowPrivateNetworks); err != nil {
			return fmt.Errorf("provider %q base_url blocked: %w", name, err)
		}
	}
	return nil
}

func validateActivationConfig(a ActivationConfig) error {
	if len(a.Sinks) == 0 {
		return nil
	}
	for i, s := range a.Sinks {
		switch strings.ToLower(strings.TrimSpace(s.Type)) {
		case "file_jsonl":
			if strings.TrimSpace(s.Path) == "" {
				return fmt.Errorf("activation sink %d (file_jsonl) missing path", i)
			}
		case "webhook":
			if strings.TrimSpace(s.URL) == "" {
				return fmt.Errorf("activation sink %d (webhook) missing url", i)
			}
			u, err := url.Parse(s.URL)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return fmt.Errorf("activation sink %d (webhook) has invalid url", i)
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				return fmt.Errorf("activation sink %d (webhook) url must be http or https", i)
			}
		default:
			return fmt.Errorf("activation sink %d has unknown type %q", i, s.Type)
		}
	}
	return nil
}

func validateTelemetryConfig(t TelemetryConfig) error {
	if !t.Enabled {
		return nil
	}
	if strings.TrimSpace(t.Endpoint) == "" {
		return errors.New("telemetry enabled but endpoint is empty")
	}
	if t.Protocol != "" {
		switch strings.ToLower(strings.TrimSpace(t.Protocol)) {
		case "grpc", "http":
		default:
			return fmt.Errorf("telemetry.protocol must be grpc or http, got %q", t.Protocol)
		}
	}
	return nil
}

func validateToolGateConfig(t ToolGateConfig) error {
	mode := strings.ToLower(strings.TrimSpace(t.Mode))
	if mode == "" {
		return nil
	}
	switch mode {
	case "elevated_only", "all_tools":
		return nil
	default:
		return fmt.Errorf("tool_gate.mode must be elevated_only or all_tools, got %q", t.Mode)
	}
}

func validateResponseGuardConfig(r ResponseGuardConfig) error {
	mode := strings.ToLower(strings.TrimSpace(r.Mode))
	if mode != "" && mode != "warn" && mode != "ignore" {
		return fmt.Errorf("response_guard.mode must be warn or ignore, got %q", r.Mode)
	}
	if err := validateResponseGuardAction("response_guard.categories.data_exfil_instruction", r.Categories.DataExfilInstruction); err != nil {
		return err
	}
	if err := validateResponseGuardAction("response_guard.categories.unsafe_action_instruction", r.Categories.UnsafeActionInstruction); err != nil {
		return err
	}
	if err := validateResponseGuardAction("response_guard.categories.privilege_escalation_instruction", r.Categories.PrivilegeEscalationInstruction); err != nil {
		return err
	}
	return nil
}

func validateResponseGuardAction(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "warn", "ignore":
		return nil
	default:
		return fmt.Errorf("%s must be warn or ignore, got %q", field, value)
	}
}

func blockPrivateHost(hostport string, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}
	host := hostport
	if strings.Contains(hostport, "]") || strings.Contains(hostport, ":") {
		h, _, err := net.SplitHostPort(hostport)
		if err == nil {
			host = h
		}
	}
	lc := strings.ToLower(strings.TrimSpace(host))
	if lc == "localhost" {
		return errors.New("private network host localhost blocked for SSRF safety")
	}

	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("private network IP %s blocked for SSRF safety", ip.String())
		}
		return nil
	}
	return nil
}

func isPrivateIP(ip net.IP) bool {
	privateBlocks := []*net.IPNet{
		{IP: net.ParseIP("127.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)},
		{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)},
		{IP: net.ParseIP("169.254.0.0"), Mask: net.CIDRMask(16, 32)},
		{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		{IP: net.ParseIP("fc00::"), Mask: net.CIDRMask(7, 128)},
		{IP: net.ParseIP("fe80::"), Mask: net.CIDRMask(10, 128)},
	}
	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
