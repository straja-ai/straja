package server

import (
	"context"
	"time"

	"github.com/straja-ai/straja/internal/policy"
	"github.com/straja-ai/straja/internal/safety"
)

type responsePIIResult struct {
	updated string
	hit     *safety.PolicyHit
	scores  map[string]float32
	latency time.Duration
}

func (s *Server) evaluateResponsePII(ctx context.Context, text string) responsePIIResult {
	if s == nil || s.policy == nil {
		return responsePIIResult{updated: text}
	}
	if p, ok := s.policy.(interface {
		EvaluateResponsePII(ctx context.Context, text string) policy.ResponsePIIResult
	}); ok {
		res := p.EvaluateResponsePII(ctx, text)
		return responsePIIResult{
			updated: res.Updated,
			hit:     res.Hit,
			scores:  res.Scores,
			latency: res.Latency,
		}
	}
	return responsePIIResult{updated: text}
}
