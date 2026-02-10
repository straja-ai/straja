package policy

import (
	"strings"

	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/safety"
)

// synthesizeMissingDetectionsFromScores fills request.StrajaGuardDetections with a minimal,
// best-effort transparency payload when we only have per-category scores.
//
// This should only ever trigger for legacy engines (or unexpected nil fields). When specialists
// are working correctly, they attach full ensemble + per-detector results.
func synthesizeMissingDetectionsFromScores(req *inference.Request, scores map[string]float32, sc config.SecurityConfig) {
	if req == nil || req.StrajaGuardDetections == nil || len(scores) == 0 {
		return
	}

	// Only synthesize for the categories that support multi-detector transparency.
	if v, ok := scores["prompt_injection"]; ok && req.StrajaGuardDetections.PromptInjection == nil {
		req.StrajaGuardDetections.PromptInjection = synthesizeCategory(sc.PromptInj.MLBlockThreshold, v)
	}
	if v, ok := scores["jailbreak"]; ok && req.StrajaGuardDetections.Jailbreak == nil {
		req.StrajaGuardDetections.Jailbreak = synthesizeCategory(sc.Jailbreak.MLBlockThreshold, v)
	}
}

func synthesizeCategory(threshold float32, score float32) *safety.CategoryDetections {
	s := score
	thr := threshold
	if thr <= 0 {
		thr = 0.8
	}
	status := "legacy_missing_details"
	kind := "legacy"

	// If the score is exactly 0, treat it as "disabled" rather than "ok".
	if strings.TrimSpace(status) == "" {
		status = "legacy_missing_details"
	}

	return &safety.CategoryDetections{
		Ensemble: safety.EnsembleResult{
			Method:         "any",
			Threshold:      thr,
			Score:          score,
			Attack:         score >= thr,
			ValidDetectors: 1,
			TotalDetectors: 1,
			Status:         status,
		},
		Detectors: []safety.DetectorResult{
			{ID: "legacy", Kind: kind, Score: &s, LatencyMs: 0},
		},
	}
}

