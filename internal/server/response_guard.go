package server

import (
	"strings"

	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/responseguard"
	"github.com/straja-ai/straja/internal/safety"
	"github.com/straja-ai/straja/internal/toolgate"
)

func (s *Server) evaluateResponseGuard(text string) responseguard.Result {
	cfg := responseguard.FromConfig(s.cfg.ResponseGuard)
	return responseguard.EvaluateResponse(text, cfg, toolgate.RuleDefs())
}

func (s *Server) applyResponseGuard(infReq *inference.Request, res responseguard.Result, streaming bool) responseguard.Result {
	if infReq == nil {
		return res
	}

	if res.Note != "" {
		infReq.ResponseNote = res.Note
	}

	if len(res.Hits) > 0 {
		if infReq.PostSafetyScores == nil {
			infReq.PostSafetyScores = make(map[string]float32, 1)
		}
		for _, hit := range res.Hits {
			if hit.Category == responseguard.CategoryDataExfilInstruction {
				infReq.PostSafetyScores[responseguard.CategoryDataExfilInstruction] = 1
			}
		}
	}

	policyHits := responseguard.HitsToPolicyHits(res.Hits)
	appendPostPolicyHits(infReq, policyHits)
	return res
}

func appendPostPolicyHits(req *inference.Request, hits []safety.PolicyHit) {
	if req == nil || len(hits) == 0 {
		return
	}
	for _, hit := range hits {
		if !containsPolicyHit(req.PostPolicyDecisions, hit.Category) {
			req.PostPolicyDecisions = append(req.PostPolicyDecisions, hit)
		}
		if !containsString(req.PostPolicyHits, hit.Category) {
			req.PostPolicyHits = append(req.PostPolicyHits, hit.Category)
		}
	}
}

func containsPolicyHit(hits []safety.PolicyHit, category string) bool {
	for _, h := range hits {
		if strings.EqualFold(h.Category, category) {
			return true
		}
	}
	return false
}
