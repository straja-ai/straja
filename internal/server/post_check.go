package server

import (
	"context"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/inference"
)

type postCheckResult struct {
	decision string
	blockErr error
	redacted bool
	outputs  []string
	postReq  *inference.Request
	latency  time.Duration
}

type postCheckAggregator struct {
	ctx     context.Context
	server  *Server
	project string
	model   string
	result  postCheckResult
}

func newPostCheckAggregator(ctx context.Context, s *Server, projectID, model string) *postCheckAggregator {
	return &postCheckAggregator{
		ctx:     ctx,
		server:  s,
		project: projectID,
		model:   model,
		result: postCheckResult{
			postReq: &inference.Request{
				ProjectID: projectID,
				Model:     model,
				Messages:  []inference.Message{},
				Timings:   &inference.Timings{},
			},
		},
	}
}

func (a *postCheckAggregator) Check(text string) (string, error) {
	req := &inference.Request{
		ProjectID: a.project,
		Model:     a.model,
		Messages: []inference.Message{
			{
				Role:    "assistant",
				Content: text,
			},
		},
		Timings: &inference.Timings{},
	}

	start := time.Now()
	err := a.server.policy.BeforeModel(a.ctx, req)
	a.result.latency += time.Since(start)

	mergeInferenceRequest(a.result.postReq, req)

	sanitized := text
	if len(req.Messages) > 0 {
		sanitized = req.Messages[0].Content
	}
	if sanitized != text {
		a.result.redacted = true
	}
	a.result.outputs = append(a.result.outputs, sanitized)

	if err != nil && a.result.blockErr == nil {
		a.result.blockErr = err
	}
	return sanitized, err
}

func (a *postCheckAggregator) Result() postCheckResult {
	if a.result.blockErr != nil {
		a.result.decision = "blocked"
	} else if a.result.redacted {
		a.result.decision = "redacted"
	} else {
		a.result.decision = "allow"
	}
	return a.result
}

func (s *Server) postCheckText(ctx context.Context, req *inference.Request, text string) (string, postCheckResult) {
	agg := newPostCheckAggregator(ctx, s, req.ProjectID, req.Model)
	updated, _ := agg.Check(text)
	res := agg.Result()
	return updated, res
}

func outputPreview(texts []string) string {
	for _, t := range texts {
		if strings.TrimSpace(t) != "" {
			return truncateText(t, 500)
		}
	}
	return ""
}

func truncateText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
