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

type capturingProvider struct {
	last *inference.Request
	resp *inference.Response
}

func (c *capturingProvider) ChatCompletion(ctx context.Context, req *inference.Request) (*inference.Response, error) {
	c.last = req
	return c.resp, nil
}

func TestChatCompletions_ToolsAndToolCalls(t *testing.T) {
	cfg := &config.Config{
		DefaultProvider: "fake",
		Providers: map[string]config.ProviderConfig{
			"fake": {Type: "fake"},
		},
		Projects: []config.ProjectConfig{
			{ID: "test-project", Provider: "fake", APIKeys: []string{"test-key-123"}},
		},
		Logging: config.LoggingConfig{ActivationLevel: "metadata"},
	}
	authz := auth.NewAuth(cfg)
	s := New(cfg, authz, "")

	cp := &capturingProvider{
		resp: &inference.Response{
			Message: inference.Message{
				Role: "assistant",
				ToolCalls: []inference.ToolCall{
					{
						ID:        "call_1",
						Type:      "function",
						Name:      "get_weather",
						Arguments: "{\"city\":\"Berlin\"}",
					},
				},
			},
			FinishReason: "tool_calls",
		},
	}
	s.providers = map[string]provider.Provider{
		"fake": cp,
	}
	s.defaultProvider = "fake"

	body := `{
		"model":"gpt-4.1-mini",
		"messages":[{"role":"user","content":"What's the weather in Berlin?"}],
		"tools":[
			{
				"type":"function",
				"function":{
					"name":"get_weather",
					"description":"Get weather for a city",
					"parameters":{"type":"object","properties":{"city":{"type":"string"}}}
				}
			}
		],
		"tool_choice":{"type":"function","function":{"name":"get_weather"}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-key-123")

	rr := httptest.NewRecorder()
	s.handleChatCompletions(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if cp.last == nil {
		t.Fatalf("provider did not receive request")
	}
	if len(cp.last.Tools) != 1 {
		t.Fatalf("expected one tool in normalized request, got %d", len(cp.last.Tools))
	}
	if cp.last.ToolChoice == nil {
		t.Fatalf("expected tool_choice in normalized request")
	}

	var parsed map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	choices, ok := parsed["choices"].([]any)
	if !ok || len(choices) == 0 {
		t.Fatalf("missing choices")
	}
	first, ok := choices[0].(map[string]any)
	if !ok {
		t.Fatalf("invalid first choice")
	}
	if first["finish_reason"] != "tool_calls" {
		t.Fatalf("expected finish_reason tool_calls, got %v", first["finish_reason"])
	}
	msg, ok := first["message"].(map[string]any)
	if !ok {
		t.Fatalf("missing message object")
	}
	tcRaw, ok := msg["tool_calls"].([]any)
	if !ok || len(tcRaw) != 1 {
		t.Fatalf("expected one tool_call in response, got %v", msg["tool_calls"])
	}
}
