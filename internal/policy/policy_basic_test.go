package policy

import (
	"context"
	"testing"

	"github.com/straja-ai/straja/internal/inference"
)

func TestBasicPolicy_BeforeModel_AllowsSafePrompt(t *testing.T) {
	p := NewBasic()
	req := &inference.Request{
		ProjectID: "test",
		Model:     "gpt-4.1-mini",
		Messages: []inference.Message{
			{Role: "user", Content: "Hello, how are you?"},
		},
	}

	err := p.BeforeModel(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error for safe prompt, got: %v", err)
	}
}

func TestBasicPolicy_BeforeModel_BlocksBannedWord(t *testing.T) {
	p := NewBasic()
	req := &inference.Request{
		ProjectID: "test",
		Model:     "gpt-4.1-mini",
		Messages: []inference.Message{
			{Role: "user", Content: "This should be blocked_test because it contains banned word."},
		},
	}

	err := p.BeforeModel(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error for banned word, got nil")
	}
}

func TestBasicPolicy_AfterModel_RedactsSensitiveWords(t *testing.T) {
	p := NewBasic()

	req := &inference.Request{
		ProjectID: "test",
		Model:     "gpt-4.1-mini",
		Messages: []inference.Message{
			{Role: "user", Content: "Tell me about passwords and tokens."},
		},
	}
	resp := &inference.Response{
		Message: inference.Message{
			Role:    "assistant",
			Content: "Here is your password and secret token.",
		},
	}

	err := p.AfterModel(context.Background(), req, resp)
	if err != nil {
		t.Fatalf("expected no error from AfterModel, got: %v", err)
	}

	if resp.Message.Content == "Here is your password and secret token." {
		t.Fatalf("expected content to be redacted, but it was unchanged")
	}

	if !contains(resp.Message.Content, "[REDACTED]") {
		t.Fatalf("expected redacted content to contain [REDACTED], got: %q", resp.Message.Content)
	}
}

// tiny helper to avoid pulling in regexp again
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(sub) > 0 && (indexOf(s, sub) >= 0)))
}

// indexOf is a minimal substring search to avoid bringing in extra dependencies.
func indexOf(s, sub string) int {
outer:
	for i := 0; i+len(sub) <= len(s); i++ {
		for j := 0; j < len(sub); j++ {
			if s[i+j] != sub[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}