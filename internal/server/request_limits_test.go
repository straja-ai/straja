package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/straja-ai/straja/internal/auth"
	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/provider"
)

type countingProvider struct {
	called int
	resp   *inference.Response
	err    error
}

func (p *countingProvider) ChatCompletion(ctx context.Context, req *inference.Request) (*inference.Response, error) {
	p.called++
	if p.err != nil {
		return nil, p.err
	}
	if p.resp != nil {
		return p.resp, nil
	}
	return &inference.Response{
		Message: inference.Message{Role: "assistant", Content: "ok"},
		Usage:   inference.Usage{TotalTokens: 1},
	}, nil
}

func baseTestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Addr:                 ":8080",
			MaxMessages:          1,
			MaxTotalMessageChars: 50,
		},
		DefaultProvider: "fake",
		Providers: map[string]config.ProviderConfig{
			"fake": {Type: "fake"},
		},
		Projects: []config.ProjectConfig{
			{
				ID:       "proj",
				Provider: "fake",
				APIKeys:  []string{"k"},
			},
		},
	}
}

func TestChatCompletion_BlocksTooManyMessages(t *testing.T) {
	cfg := baseTestConfig()
	authz := auth.NewAuth(cfg)
	s := New(cfg, authz)
	cp := &countingProvider{}
	s.providers = map[string]provider.Provider{"fake": cp}
	s.defaultProvider = "fake"

	body := `{
		"model": "gpt-4",
		"messages": [{"role":"user","content":"hi"},{"role":"user","content":"again"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer k")
	rr := httptest.NewRecorder()

	s.handleChatCompletions(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if cp.called != 0 {
		t.Fatalf("provider should not be called on blocked request")
	}
}

func TestChatCompletion_BlocksTooManyChars(t *testing.T) {
	cfg := baseTestConfig()
	cfg.Server.MaxTotalMessageChars = 5
	authz := auth.NewAuth(cfg)
	s := New(cfg, authz)
	cp := &countingProvider{}
	s.providers = map[string]provider.Provider{"fake": cp}
	s.defaultProvider = "fake"

	body := `{
		"model": "gpt-4",
		"messages": [{"role":"user","content":"123456"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer k")
	rr := httptest.NewRecorder()

	s.handleChatCompletions(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if cp.called != 0 {
		t.Fatalf("provider should not be called on blocked request")
	}
}

func TestChatCompletion_ModelAllowlistBlocks(t *testing.T) {
	cfg := baseTestConfig()
	cfg.Projects[0].AllowedModels = []string{"allowed-model"}
	authz := auth.NewAuth(cfg)
	s := New(cfg, authz)
	cp := &countingProvider{}
	s.providers = map[string]provider.Provider{"fake": cp}
	s.defaultProvider = "fake"

	body := `{
		"model": "blocked-model",
		"messages": [{"role":"user","content":"hi"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer k")
	rr := httptest.NewRecorder()

	s.handleChatCompletions(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if cp.called != 0 {
		t.Fatalf("provider should not be called when model blocked")
	}
}

func TestChatCompletion_WithinLimitsPasses(t *testing.T) {
	cfg := baseTestConfig()
	cfg.Server.MaxMessages = 3
	cfg.Server.MaxRequestBodyBytes = 1024
	authz := auth.NewAuth(cfg)
	s := New(cfg, authz)
	cp := &countingProvider{}
	s.providers = map[string]provider.Provider{"fake": cp}
	s.defaultProvider = "fake"

	body := `{
		"model": "gpt-4",
		"messages": [{"role":"user","content":"hi"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer k")
	rr := httptest.NewRecorder()

	s.handleChatCompletions(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if cp.called != 1 {
		t.Fatalf("expected provider called once, got %d", cp.called)
	}

	var parsed map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
}

func TestChatCompletion_BlocksLargeBody(t *testing.T) {
	cfg := baseTestConfig()
	cfg.Server.MaxRequestBodyBytes = 50
	authz := auth.NewAuth(cfg)
	s := New(cfg, authz)
	cp := &countingProvider{}
	s.providers = map[string]provider.Provider{"fake": cp}
	s.defaultProvider = "fake"

	largeContent := bytes.Repeat([]byte("a"), 100)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"` + string(largeContent) + `"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer k")
	rr := httptest.NewRecorder()

	s.handleChatCompletions(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
	if cp.called != 0 {
		t.Fatalf("provider should not be called on blocked request")
	}
}
