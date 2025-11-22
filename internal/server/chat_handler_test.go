package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/straja-ai/straja/internal/auth"
	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/provider"
)

func TestChatCompletion_SimplePath(t *testing.T) {
	// ---- 1) Config with a single fake provider ----
	cfg := &config.Config{
		DefaultProvider: "fake",
		Providers: map[string]config.ProviderConfig{
			"fake": {
				Type: "fake",
			},
		},
		Projects: []config.ProjectConfig{
			{
				ID:       "test-project",
				Provider: "fake",
				APIKeys:  []string{"test-key-123"},
			},
		},
		Logging: config.LoggingConfig{
			ActivationLevel: "metadata",
		},
	}

	// ---- 2) Auth setup (map API key -> project) ----
	authz := auth.NewAuth(cfg)

	// ---- 3) Override provider registry for this test ----
	s := New(cfg, authz)
	s.providers = map[string]provider.Provider{
		"fake": provider.NewFake("Hello from fake"),
	}
	s.defaultProvider = "fake"

	// ---- 4) Build HTTP request ----
	body := `{
		"model": "gpt-4.1-mini",
		"messages": [{"role":"user", "content":"Hello"}]
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-key-123")

	rr := httptest.NewRecorder()

	// ---- 5) Serve request ----
	s.handleChatCompletions(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// ---- 6) Assert OpenAI structure ----
	if parsed["object"] != "chat.completion" {
		t.Fatalf("expected object=chat.completion, got %v", parsed["object"])
	}

	choices := parsed["choices"].([]interface{})
	first := choices[0].(map[string]interface{})
	msg := first["message"].(map[string]interface{})

	if msg["content"] != "Hello from fake" {
		t.Fatalf("expected fake response, got %v", msg["content"])
	}
}
