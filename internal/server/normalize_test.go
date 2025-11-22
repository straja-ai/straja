package server

import (
	"reflect"
	"testing"

	"github.com/straja-ai/straja/internal/inference"
)

func TestNormalizeToInferenceRequest(t *testing.T) {
	req := &chatCompletionRequest{
		Model: "gpt-4.1-mini",
		Messages: []chatMessage{
			{Role: "user", Content: "Hello"},
			{Role: "assistant", Content: "Hi there"},
		},
	}

	got := normalizeToInferenceRequest("project-123", req)

	if got.ProjectID != "project-123" {
		t.Fatalf("expected ProjectID=project-123, got %q", got.ProjectID)
	}
	if got.Model != "gpt-4.1-mini" {
		t.Fatalf("expected Model=gpt-4.1-mini, got %q", got.Model)
	}
	if got.UserID != "" {
		t.Fatalf("expected UserID to be empty, got %q", got.UserID)
	}

	wantMsgs := []inference.Message{
		{Role: "user", Content: "Hello"},
		{Role: "assistant", Content: "Hi there"},
	}
	if !reflect.DeepEqual(got.Messages, wantMsgs) {
		t.Fatalf("messages mismatch.\n got:  %#v\n want: %#v", got.Messages, wantMsgs)
	}
}
