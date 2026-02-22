package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/straja-ai/straja-gateway/internal/inference"
)

func TestOpenAIProviderChatCompletion_ToolCalls(t *testing.T) {
	var gotBody map[string]any

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer provider-key" {
			t.Fatalf("missing provider auth header")
		}
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl_1",
			"object":"chat.completion",
			"choices":[
				{
					"index":0,
					"message":{
						"role":"assistant",
						"content":"",
						"tool_calls":[
							{
								"id":"call_1",
								"type":"function",
								"function":{"name":"get_weather","arguments":"{\"city\":\"Berlin\"}"}
							}
						]
					},
					"finish_reason":"tool_calls"
				}
			],
			"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}
		}`))
	}))
	t.Cleanup(upstream.Close)

	p := NewOpenAI(upstream.URL+"/v1", "provider-key", 2*time.Second, 1024*1024)
	req := &inference.Request{
		Model: "gpt-4.1-mini",
		Messages: []inference.Message{
			{Role: "user", Content: "What's the weather?"},
		},
		Tools: []inference.ToolDef{
			{
				"type": "function",
				"function": map[string]any{
					"name":       "get_weather",
					"parameters": map[string]any{"type": "object"},
				},
			},
		},
		ToolChoice: map[string]any{
			"type": "function",
			"function": map[string]any{
				"name": "get_weather",
			},
		},
	}

	resp, err := p.ChatCompletion(context.Background(), req)
	if err != nil {
		t.Fatalf("ChatCompletion error: %v", err)
	}
	if resp.FinishReason != "tool_calls" {
		t.Fatalf("expected finish_reason tool_calls, got %q", resp.FinishReason)
	}
	if len(resp.Message.ToolCalls) != 1 {
		t.Fatalf("expected one tool call, got %d", len(resp.Message.ToolCalls))
	}
	if resp.Message.ToolCalls[0].Name != "get_weather" {
		t.Fatalf("unexpected tool call name: %s", resp.Message.ToolCalls[0].Name)
	}

	if _, ok := gotBody["tools"]; !ok {
		t.Fatalf("expected tools in upstream payload")
	}
	if _, ok := gotBody["tool_choice"]; !ok {
		t.Fatalf("expected tool_choice in upstream payload")
	}
}
