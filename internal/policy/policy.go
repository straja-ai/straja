package policy

import (
 "context"

 "github.com/straja-ai/straja/internal/inference"
)

// Engine defines the interface for Straja's policy engine.
// It runs before and after the upstream LLM call.
type Engine interface {
 // BeforeModel runs on the normalized request before calling the model.
 // It can mutate the request (e.g. redact PII) or return an error to block.
 BeforeModel(ctx context.Context, req *inference.Request) error

 // AfterModel runs on the normalized response after calling the model.
 // It can mutate the response (e.g. redact) or return an error to block.
 AfterModel(ctx context.Context, req *inference.Request, resp *inference.Response) error
}

// noopEngine is the simplest possible implementation: it does nothing.
type noopEngine struct{}

// NewNoop returns a policy engine that performs no checks or modifications.
func NewNoop() Engine {
 return &noopEngine{}
}

func (n *noopEngine) BeforeModel(ctx context.Context, req *inference.Request) error {
 // no-op for now
 return nil
}

func (n *noopEngine) AfterModel(ctx context.Context, req *inference.Request, resp *inference.Response) error {
 // no-op for now
 return nil
}
