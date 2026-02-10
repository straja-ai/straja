package activation

import (
	"encoding/json"
	"testing"

	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/safety"
)

func TestActivationPayload_IncludesDetectorDetails_Additive(t *testing.T) {
	req := &inference.Request{
		RequestID: "req1",
		ProjectID: "p1",
		Model:     "m1",
		SecurityScores: map[string]float32{
			"prompt_injection": 0.5,
			"jailbreak":        0.7,
		},
		StrajaGuardDetections: &safety.StrajaGuardDetections{
			PromptInjection: &safety.CategoryDetections{
				Ensemble: safety.EnsembleResult{Method: "any", Threshold: 0.8, Score: 0.5, Attack: false, ValidDetectors: 1, TotalDetectors: 1, Status: "ok"},
				Detectors: []safety.DetectorResult{
					{ID: "pi_deberta_v3", Kind: "sequence_classification", ModelRef: "prompt_injection/model.onnx", Score: f32(0.5), LatencyMs: 12},
				},
			},
			Jailbreak: &safety.CategoryDetections{
				Ensemble: safety.EnsembleResult{Method: "any", Threshold: 0.8, Score: 0.7, Attack: false, ValidDetectors: 2, TotalDetectors: 2, Status: "ok"},
				Detectors: []safety.DetectorResult{
					{ID: "jb_v1", Kind: "sequence_classification", ModelRef: "jailbreak/model.onnx", Score: f32(0.6), LatencyMs: 10},
					{ID: "jb_2xl", Kind: "qwen_next_token", ModelRef: "jailbreak2xl/model.onnx", Score: f32(0.7), LatencyMs: 30},
				},
			},
		},
	}

	ev := BuildEvent(BuildParams{
		Request:      req,
		ProviderName: "prov",
		Decision:     DecisionAllow,
	})
	if ev == nil {
		t.Fatalf("expected event, got nil")
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("decode event: %v", err)
	}
	reqObj, _ := decoded["request"].(map[string]any)
	if reqObj == nil {
		t.Fatalf("missing request object")
	}
	sgObj, _ := reqObj["strajaguard"].(map[string]any)
	if sgObj == nil {
		t.Fatalf("missing request.strajaguard")
	}
	if _, ok := sgObj["prompt_injection"]; !ok {
		t.Fatalf("missing request.strajaguard.prompt_injection")
	}
	if _, ok := sgObj["jailbreak"]; !ok {
		t.Fatalf("missing request.strajaguard.jailbreak")
	}
}

func f32(v float32) *float32 { return &v }

