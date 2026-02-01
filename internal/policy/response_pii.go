package policy

import (
	"context"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/safety"
	"github.com/straja-ai/straja/internal/strajaguard"
)

// ResponsePIIResult captures response-side PII evaluation results.
type ResponsePIIResult struct {
	Updated string
	Hit     *safety.PolicyHit
	Scores  map[string]float32
	Latency time.Duration
}

// EvaluateResponsePII runs PII-only evaluation on response text and applies redaction when configured.
func (p *Basic) EvaluateResponsePII(ctx context.Context, text string) ResponsePIIResult {
	res := ResponsePIIResult{Updated: text}
	if strings.TrimSpace(text) == "" {
		return res
	}

	var signals []safety.DetectionSignal
	scores := map[string]float32{}
	var piiEntities []safety.PIIEntity
	start := time.Now()

	useRegex := true
	if p.securityCfg.Enabled && p.sp != nil {
		useRegex = false
		if out, err := p.sp.AnalyzeText(ctx, text); err == nil && out != nil {
			if score, ok := out.Scores["contains_personal_data"]; ok {
				scores["contains_personal_data"] = score
				signals = append(signals, safety.DetectionSignal{
					Category:   "contains_personal_data",
					Source:     strajaguard.SpecialistSourcePIINER,
					Confidence: score,
				})
			}
			if len(out.PIIEntities) > 0 {
				piiEntities = out.PIIEntities
			}
		}
	} else if p.securityCfg.Enabled && p.sg != nil {
		useRegex = false
		if out, err := p.sg.Evaluate("", text); err == nil && out != nil {
			if score, ok := out.Scores["contains_personal_data"]; ok {
				scores["contains_personal_data"] = score
				signals = append(signals, safety.DetectionSignal{
					Category:   "contains_personal_data",
					Source:     "ml_strajaguard_v1",
					Confidence: score,
				})
			}
		}
	}

	if useRegex && p.intel != nil {
		if out, err := p.intel.AnalyzeInput(ctx, text); err == nil && out != nil {
			if cat, ok := out.Categories["pii"]; ok && cat.Hit {
				signals = append(signals, safety.DetectionSignal{
					Category:   "pii",
					Source:     "regex",
					Confidence: 1.0,
				})
			}
		}
	}

	res.Latency = time.Since(start)
	if len(scores) > 0 {
		res.Scores = scores
	}

	hit := safety.EvaluatePII(signals, p.securityCfg.PII)
	if hit == nil {
		return res
	}

	updated := text
	redacted := false
	if shouldRedactResponsePII(hit.Action) {
		if len(piiEntities) > 0 {
			if out, changed := redactWithEntities(text, piiEntities); changed {
				updated = out
				redacted = true
			}
		}
		if !redacted {
			if bundle, ok := p.intel.(interface {
				RedactInput(category, text string) (string, bool)
			}); ok {
				if out, changed := bundle.RedactInput("pii", text); changed {
					updated = out
					redacted = true
				}
			}
		}
	}

	res.Updated = updated
	res.Hit = normalizeResponsePIIHit(hit, redacted)
	return res
}

func shouldRedactResponsePII(action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "redact", "block", "block_and_redact":
		return true
	default:
		return false
	}
}

func normalizeResponsePIIHit(hit *safety.PolicyHit, redacted bool) *safety.PolicyHit {
	if hit == nil {
		return nil
	}
	out := *hit
	action := strings.ToLower(strings.TrimSpace(out.Action))
	if action == "block" || action == "block_and_redact" {
		if redacted {
			out.Action = "redact"
		} else {
			out.Action = "warn"
		}
	}
	return &out
}
