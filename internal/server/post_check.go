package server

import (
	"context"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/inference"
)

type postCheckResult struct {
	decision string
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

func newPostCheckAggregator(ctx context.Context, s *Server, projectID, model, requestID string) *postCheckAggregator {
	return &postCheckAggregator{
		ctx:     ctx,
		server:  s,
		project: projectID,
		model:   model,
		result: postCheckResult{
			postReq: &inference.Request{
				RequestID: requestID,
				ProjectID: projectID,
				Model:     model,
				Messages:  []inference.Message{},
				Timings:   &inference.Timings{},
			},
		},
	}
}

func (a *postCheckAggregator) Check(text string) (string, error) {
	piiRes := a.server.evaluateResponsePII(a.ctx, text)
	a.result.latency += piiRes.latency

	sanitized := text
	if piiRes.updated != "" {
		sanitized = piiRes.updated
	}
	if sanitized != text {
		a.result.redacted = true
	}
	a.result.outputs = append(a.result.outputs, sanitized)

	if piiRes.hit != nil {
		if !containsPolicyHit(a.result.postReq.PolicyDecisions, piiRes.hit.Category) {
			a.result.postReq.PolicyDecisions = append(a.result.postReq.PolicyDecisions, *piiRes.hit)
		}
		if !containsString(a.result.postReq.PolicyHits, piiRes.hit.Category) {
			a.result.postReq.PolicyHits = append(a.result.postReq.PolicyHits, piiRes.hit.Category)
		}
	}
	if len(piiRes.scores) > 0 {
		if a.result.postReq.SecurityScores == nil {
			a.result.postReq.SecurityScores = make(map[string]float32, len(piiRes.scores))
		}
		for k, v := range piiRes.scores {
			a.result.postReq.SecurityScores[k] = v
		}
	}
	return sanitized, nil
}

func (a *postCheckAggregator) Result() postCheckResult {
	if a.result.redacted {
		a.result.decision = "redacted"
	} else {
		a.result.decision = "allow"
	}
	return a.result
}

func (s *Server) postCheckText(ctx context.Context, req *inference.Request, text string) (string, postCheckResult) {
	reqID := ""
	if req != nil {
		reqID = req.RequestID
	}
	agg := newPostCheckAggregator(ctx, s, req.ProjectID, req.Model, reqID)
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
