package mockprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestMockProviderChatCompletions(t *testing.T) {
	shutdown, baseURL, err := StartMockProvider("127.0.0.1:0")
	if err != nil {
		t.Skipf("start mock provider: %v", err)
	}
	defer shutdown(context.Background())

	payload := []byte(`{"model":"mock-llm","messages":[{"role":"user","content":"hi"}]}`)
	resp, err := http.Post(baseURL+"/v1/chat/completions", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("post mock provider: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var body struct {
		ID      string `json:"id"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
				Role    string `json:"role"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ID == "" {
		t.Fatalf("expected non-empty id")
	}
	if len(body.Choices) == 0 {
		t.Fatalf("expected at least one choice")
	}
	if body.Choices[0].Message.Content == "" {
		t.Fatalf("expected non-empty content")
	}
}
