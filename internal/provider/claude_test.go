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

func TestClaudeProviderChatCompletion(t *testing.T) {
	var gotPath string
	var gotAPIKey string
	var gotVersion string
	var gotBody map[string]any

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAPIKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")

		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":4,"output_tokens":2}}`))
	}))
	t.Cleanup(upstream.Close)

	p := NewClaude(upstream.URL+"/v1", "provider-key", 2*time.Second, 1024*1024)
	req := &inference.Request{
		Model: "claude-3-5-sonnet-latest",
		Messages: []inference.Message{
			{Role: "system", Content: "be concise"},
			{Role: "user", Content: "hello"},
		},
	}

	resp, err := p.ChatCompletion(context.Background(), req)
	if err != nil {
		t.Fatalf("ChatCompletion error: %v", err)
	}
	if resp.Message.Content != "ok" {
		t.Fatalf("expected response content ok, got %q", resp.Message.Content)
	}
	if resp.Usage.TotalTokens != 6 {
		t.Fatalf("expected total tokens 6, got %d", resp.Usage.TotalTokens)
	}
	if gotPath != "/v1/messages" {
		t.Fatalf("expected request path /v1/messages, got %q", gotPath)
	}
	if gotAPIKey != "provider-key" {
		t.Fatalf("expected x-api-key provider-key, got %q", gotAPIKey)
	}
	if gotVersion != defaultClaudeVersion {
		t.Fatalf("expected anthropic-version %s, got %q", defaultClaudeVersion, gotVersion)
	}
	if gotBody["model"] != "claude-3-5-sonnet-latest" {
		t.Fatalf("unexpected model in payload: %v", gotBody["model"])
	}
}
