package strajaguard

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/straja-ai/straja/internal/safety"
)

func TestEntitiesFromTokenLabels_EmailSpan(t *testing.T) {
	text := "contact me at test@example.com please"
	email := "test@example.com"
	start := strings.Index(text, email)
	if start < 0 {
		t.Fatalf("email not found in test text")
	}
	end := start + len(email)

	labels := []string{"B-EMAIL"}
	offsets := []tokenOffset{{Start: start, End: end}}
	entities := entitiesFromTokenLabels(labels, offsets)
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(entities))
	}
	ent := entities[0]
	if ent.EntityType != "EMAIL" {
		t.Fatalf("expected EMAIL entity, got %s", ent.EntityType)
	}
	if ent.StartByte != start || ent.EndByte != end {
		t.Fatalf("expected span %d-%d, got %d-%d", start, end, ent.StartByte, ent.EndByte)
	}
	if ent.Source != SpecialistEntitySource {
		t.Fatalf("expected source %s, got %s", SpecialistEntitySource, ent.Source)
	}
}

func TestLoadSpecialistsConfig(t *testing.T) {
	cfgPath := filepath.Join("..", "..", "configs", "strajaguard_specialists.yaml")
	cfg, err := LoadSpecialistsConfig(cfgPath)
	if err != nil {
		t.Fatalf("load specialists config: %v", err)
	}
	if cfg == nil || len(cfg.Specialists) != 3 {
		t.Fatalf("expected 3 specialists, got %d", len(cfg.Specialists))
	}
	expect := map[string]string{
		"prompt_injection": "sequence_classification",
		"jailbreak":        "sequence_classification",
		"pii_ner":          "token_classification",
	}
	for id, kind := range expect {
		spec, ok := cfg.Specialists[id]
		if !ok {
			t.Fatalf("missing specialist %s", id)
		}
		if spec.Kind != kind {
			t.Fatalf("expected %s kind %s, got %s", id, kind, spec.Kind)
		}
	}
}

func TestMergeEntities(t *testing.T) {
	in := []safety.PIIEntity{
		{EntityType: "EMAIL", StartByte: 5, EndByte: 10, Source: SpecialistEntitySource},
		{EntityType: "EMAIL", StartByte: 10, EndByte: 15, Source: SpecialistEntitySource},
	}
	out := mergeEntities(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 merged entity, got %d", len(out))
	}
	if out[0].StartByte != 5 || out[0].EndByte != 15 {
		t.Fatalf("expected merged span 5-15, got %d-%d", out[0].StartByte, out[0].EndByte)
	}
}

func TestSpecialistsEngineSessionReuse(t *testing.T) {
	bundleDir := strings.TrimSpace(os.Getenv("STRAJA_SPECIALISTS_BUNDLE_DIR"))
	if bundleDir == "" {
		t.Skip("STRAJA_SPECIALISTS_BUNDLE_DIR not set; skipping ONNX runtime test")
	}

	rt := ResolveRuntime(RuntimeConfig{})
	engine, err := LoadSpecialistsEngine(bundleDir, 64, rt, "configs/strajaguard_specialists.yaml")
	if err != nil {
		t.Fatalf("load specialists engine: %v", err)
	}
	for id, m := range engine.models {
		if m.poolSize != 1 || cap(m.sessions) != 1 {
			t.Fatalf("expected single session for %s, got pool_size=%d cap=%d", id, m.poolSize, cap(m.sessions))
		}
	}
	if _, err := engine.AnalyzeText(context.Background(), "hello"); err != nil {
		t.Fatalf("analyze text: %v", err)
	}
	if _, err := engine.AnalyzeText(context.Background(), "hello again"); err != nil {
		t.Fatalf("analyze text second pass: %v", err)
	}
	for id, m := range engine.models {
		if len(m.sessions) != m.poolSize {
			t.Fatalf("expected sessions returned for %s, got %d/%d", id, len(m.sessions), m.poolSize)
		}
	}
}

func TestSequenceScoreAttackClassSelection(t *testing.T) {
	meta := specialistMeta{
		ID2Label: map[int]string{
			0: "safe",
			1: "prompt_injection",
		},
		NumLabels: 2,
	}
	attackIdx, _ := pickAttackClass("prompt_injection", meta, 2)
	if attackIdx != 1 {
		t.Fatalf("expected attack class index 1, got %d", attackIdx)
	}

	rawBenign := []float32{5.0, -5.0} // safe high
	score, _, _, _ := sequenceScore(rawBenign, 2, []int64{1, 2}, attackIdx, "prompt_injection", "prompt_injection")
	if score >= 0.8 {
		t.Fatalf("expected benign score < 0.8, got %.4f", score)
	}

	rawAttack := []float32{-5.0, 5.0} // attack high
	score, _, _, _ = sequenceScore(rawAttack, 2, []int64{1, 2}, attackIdx, "prompt_injection", "prompt_injection")
	if score <= 0.6 {
		t.Fatalf("expected attack score > 0.6, got %.4f", score)
	}
}

func TestSequenceScoreJailbreakThresholds(t *testing.T) {
	meta := specialistMeta{
		ID2Label: map[int]string{
			0: "safe",
			1: "jailbreak",
		},
		NumLabels: 2,
	}
	attackIdx, _ := pickAttackClass("jailbreak", meta, 2)
	if attackIdx != 1 {
		t.Fatalf("expected attack class index 1, got %d", attackIdx)
	}
	rawBenign := []float32{4.0, -4.0}
	score, _, _, _ := sequenceScore(rawBenign, 2, []int64{1, 2}, attackIdx, "jailbreak", "jailbreak")
	if score >= 0.8 {
		t.Fatalf("expected benign score < 0.8, got %.4f", score)
	}
	rawAttack := []float32{-4.0, 4.0}
	score, _, _, _ = sequenceScore(rawAttack, 2, []int64{1, 2}, attackIdx, "jailbreak", "jailbreak")
	if score <= 0.6 {
		t.Fatalf("expected attack score > 0.6, got %.4f", score)
	}
}

func TestPickAttackClassUsesLabel2ID(t *testing.T) {
	meta := specialistMeta{
		Label2ID: map[string]int{
			"safe":             0,
			"prompt_injection": 1,
		},
		NumLabels: 2,
		ID2Label:  labelsMapFromLabel2ID(map[string]int{"safe": 0, "prompt_injection": 1}),
	}
	attackIdx, _ := pickAttackClass("prompt_injection", meta, 2)
	if attackIdx != 1 {
		t.Fatalf("expected attack class index 1, got %d", attackIdx)
	}
}
