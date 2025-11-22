package provider

import (
	"context"

	"github.com/straja-ai/straja/internal/inference"
)

type FakeProvider struct {
	ResponseText string
	Error        error
}

func (f *FakeProvider) ChatCompletion(ctx context.Context, req *inference.Request) (*inference.Response, error) {
	if f.Error != nil {
		return nil, f.Error
	}

	return &inference.Response{
		Message: inference.Message{
			Role:    "assistant",
			Content: f.ResponseText,
		},
		Usage: inference.Usage{
			PromptTokens:     2,
			CompletionTokens: 3,
			TotalTokens:      5,
		},
	}, nil
}

func NewFake(response string) *FakeProvider {
	return &FakeProvider{ResponseText: response}
}