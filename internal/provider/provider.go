package provider

import (
 "context"

 "github.com/somanole/straja/internal/inference"
)

// Provider is the interface for all upstream LLM providers.
type Provider interface {
 ChatCompletion(ctx context.Context, req *inference.Request) (*inference.Response, error)
}

// echoProvider is a simple stub provider that simulates an LLM.
// We'll replace this with a real OpenAI provider soon.
type echoProvider struct{}

// NewEcho creates a new stub provider.
func NewEcho() Provider {
 return &echoProvider{}
}

func (p *echoProvider) ChatCompletion(ctx context.Context, req *inference.Request) (*inference.Response, error) {
 // For now we ignore model, project, etc., and just respond with a static message.
 // You could also echo part of the user content if you want.
 return &inference.Response{
  Message: inference.Message{
   Role:    "assistant",
   Content: "Hello from Straja skeleton provider! (Later this will call a real LLM like OpenAI.)",
  },
  Usage: inference.Usage{
   PromptTokens:     0,
   CompletionTokens: 0,
   TotalTokens:      0,
  },
 }, nil
}
