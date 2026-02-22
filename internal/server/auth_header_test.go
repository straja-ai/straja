package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/straja-ai/straja-gateway/internal/config"
	"github.com/straja-ai/straja-gateway/internal/provider"
)

func TestParseBearerToken_Valid(t *testing.T) {
	token, ok := parseBearerToken("Bearer abc123")
	if !ok {
		t.Fatalf("expected ok=true for valid header")
	}
	if token != "abc123" {
		t.Fatalf("expected token 'abc123', got %q", token)
	}
}

func TestParseBearerToken_CaseInsensitiveScheme(t *testing.T) {
	token, ok := parseBearerToken("bearer xyz")
	if !ok || token != "xyz" {
		t.Fatalf("expected ok=true and token 'xyz', got ok=%v token=%q", ok, token)
	}
}

func TestParseBearerToken_InvalidFormats(t *testing.T) {
	cases := []string{
		"",
		"abc123",
		"Bearer",
		"Bearer ",
		"Token abc123",
		"Bearer abc def",
	}

	for _, h := range cases {
		if token, ok := parseBearerToken(h); ok || token != "" {
			t.Fatalf("expected failure for header %q, got ok=%v token=%q", h, ok, token)
		}
	}
}

func TestResolveAuthProject_XAPIKeyHeader(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Server.MaxRequestBodyBytes = 1024
	cfg.Providers = map[string]config.ProviderConfig{
		"echo": {Type: "openai", APIKey: "upstream-key", BaseURL: "https://api.openai.com/v1"},
	}
	cfg.DefaultProvider = "echo"

	srv := newTestServer(t, cfg)
	srv.providers["echo"] = provider.NewFake("ok")

	body := `{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "test-key")

	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for x-api-key auth, got %d", rr.Code)
	}
}
