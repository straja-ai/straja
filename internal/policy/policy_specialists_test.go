package policy

import (
	"context"
	"testing"

	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/intel"
	"github.com/straja-ai/straja/internal/safety"
	"github.com/straja-ai/straja/internal/strajaguard"
	"go.opentelemetry.io/otel/trace"
)

type fakeSpecialists struct {
	result *strajaguard.SpecialistsResult
	err    error
}

func (f *fakeSpecialists) AnalyzeText(ctx context.Context, text string) (*strajaguard.SpecialistsResult, error) {
	return f.result, f.err
}

func TestBasicPolicy_SpecialistsHits(t *testing.T) {
	sec := config.SecurityConfig{
		Enabled: true,
		PromptInj: config.SecurityCategoryConfig{
			RegexEnabled:     false,
			MLEnabled:        true,
			MLWarnThreshold:  0.5,
			MLBlockThreshold: 0.8,
			ActionOnBlock:    "block",
		},
		Jailbreak: config.SecurityCategoryConfig{
			RegexEnabled:     false,
			MLEnabled:        true,
			MLWarnThreshold:  0.5,
			MLBlockThreshold: 0.8,
			ActionOnBlock:    "block",
		},
		PII: config.PIICategoryConfig{
			RegexEnabled:    false,
			MLEnabled:       true,
			MLWarnThreshold: 0.5,
			Action:          "redact",
		},
	}

	fake := &fakeSpecialists{
		result: &strajaguard.SpecialistsResult{
			Scores: map[string]float32{
				"prompt_injection":       0.95,
				"jailbreak":              0.92,
				"contains_personal_data": 1.0,
			},
			Detections: &safety.StrajaGuardDetections{
				PromptInjection: &safety.CategoryDetections{
					Ensemble: safety.EnsembleResult{
						Method:         "any",
						Threshold:      0.8,
						Score:          0.95,
						Attack:         true,
						ValidDetectors: 1,
						TotalDetectors: 1,
						Status:         "ok",
					},
					Detectors: []safety.DetectorResult{
						{ID: "pi_deberta_v3", Kind: "sequence_classification", ModelRef: "prompt_injection/model.onnx", Score: f32(0.95), LatencyMs: 10},
					},
				},
				Jailbreak: &safety.CategoryDetections{
					Ensemble: safety.EnsembleResult{
						Method:         "any",
						Threshold:      0.8,
						Score:          0.92,
						Attack:         true,
						ValidDetectors: 2,
						TotalDetectors: 2,
						Status:         "ok",
					},
					Detectors: []safety.DetectorResult{
						{ID: "jb_v1", Kind: "sequence_classification", ModelRef: "jailbreak/model.onnx", Score: f32(0.9), LatencyMs: 12},
						{ID: "jb_2xl", Kind: "qwen_next_token", ModelRef: "jailbreak2xl/model.onnx", Score: f32(0.92), LatencyMs: 30},
					},
				},
			},
			PIIEntities: []safety.PIIEntity{
				{EntityType: "EMAIL", StartByte: 5, EndByte: 15, Source: "pii_ner"},
			},
		},
	}

	p := NewBasic(config.PolicyConfig{}, sec, intel.NewNoop(), nil, fake, trace.NewNoopTracerProvider().Tracer("test"), config.StrajaGuardConfig{})

	req := &inference.Request{
		ProjectID: "p1",
		Model:     "test",
		Messages: []inference.Message{
			{Role: "user", Content: "hello test@example.com"},
		},
		Timings: &inference.Timings{},
	}

	if err := p.BeforeModel(context.Background(), req); err == nil {
		t.Fatalf("expected block error due to prompt_injection/jailbreak")
	}

	if !hasCategory(req.PolicyDecisions, "prompt_injection") {
		t.Fatalf("expected prompt_injection decision")
	}
	if !hasCategory(req.PolicyDecisions, "jailbreak") {
		t.Fatalf("expected jailbreak decision")
	}
	if !hasCategory(req.PolicyDecisions, "pii") {
		t.Fatalf("expected pii decision")
	}

	promptSources := sourcesFor(req.PolicyDecisions, "prompt_injection")
	if !containsStr(promptSources, strajaguard.SpecialistSourcePromptInjection) {
		t.Fatalf("expected prompt_injection source %s, got %v", strajaguard.SpecialistSourcePromptInjection, promptSources)
	}
	jbSources := sourcesFor(req.PolicyDecisions, "jailbreak")
	if !containsStr(jbSources, strajaguard.SpecialistSourceJailbreak) {
		t.Fatalf("expected jailbreak source %s, got %v", strajaguard.SpecialistSourceJailbreak, jbSources)
	}
	piiSources := sourcesFor(req.PolicyDecisions, "pii")
	if !containsStr(piiSources, strajaguard.SpecialistSourcePIINER) {
		t.Fatalf("expected pii source %s, got %v", strajaguard.SpecialistSourcePIINER, piiSources)
	}

	if req.StrajaGuardDetections == nil {
		t.Fatalf("expected StrajaGuardDetections to be populated")
	}
	if req.StrajaGuardDetections.Jailbreak == nil || len(req.StrajaGuardDetections.Jailbreak.Detectors) != 2 {
		t.Fatalf("expected jailbreak detector details to be present, got %+v", req.StrajaGuardDetections.Jailbreak)
	}
	if req.StrajaGuardDetections.PromptInjection == nil || len(req.StrajaGuardDetections.PromptInjection.Detectors) != 1 {
		t.Fatalf("expected prompt_injection detector details to be present, got %+v", req.StrajaGuardDetections.PromptInjection)
	}
}

func hasCategory(hits []safety.PolicyHit, category string) bool {
	for _, h := range hits {
		if h.Category == category {
			return true
		}
	}
	return false
}

func sourcesFor(hits []safety.PolicyHit, category string) []string {
	for _, h := range hits {
		if h.Category == category {
			return h.Sources
		}
	}
	return nil
}

func containsStr(list []string, val string) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}

func f32(v float32) *float32 { return &v }
