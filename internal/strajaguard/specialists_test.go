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
	if cfg == nil {
		t.Fatalf("expected config, got nil")
	}
	if len(cfg.Detectors.PromptInjection) != 3 {
		t.Fatalf("expected 3 prompt_injection detectors, got %d", len(cfg.Detectors.PromptInjection))
	}
	if len(cfg.Detectors.Jailbreak) != 2 {
		t.Fatalf("expected 2 jailbreak detectors, got %d", len(cfg.Detectors.Jailbreak))
	}
	assertDetectorIDs(t, cfg.Detectors.PromptInjection, []string{"prompt_injection_deberta_v3", "prompt_injection_vijil", "prompt_injection_hedgehog"})
	assertDetectorIDs(t, cfg.Detectors.Jailbreak, []string{"jailbreak_jackhhao", "jailbreak2xl"})
	assertDetectorEnabled(t, cfg.Detectors.PromptInjection, "prompt_injection_deberta_v3", false)
	assertDetectorEnabled(t, cfg.Detectors.PromptInjection, "prompt_injection_vijil", true)
	assertDetectorEnabled(t, cfg.Detectors.PromptInjection, "prompt_injection_hedgehog", false)
	assertDetectorEnabled(t, cfg.Detectors.Jailbreak, "jailbreak_jackhhao", false)
	assertDetectorEnabled(t, cfg.Detectors.Jailbreak, "jailbreak2xl", true)
	assertAttackIdx(t, cfg.Detectors.PromptInjection, "prompt_injection_vijil", 1)
	assertAttackIdx(t, cfg.Detectors.Jailbreak, "jailbreak_jackhhao", 1)
	if _, ok := cfg.Specialists["pii_ner"]; !ok {
		t.Fatalf("missing pii_ner specialist")
	}
}

func TestLoadSpecialistsConfigFallbackEmbedded(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing.yaml")
	cfg, source, err := loadSpecialistsConfigWithFallback(missingPath)
	if err != nil {
		t.Fatalf("load specialists config fallback: %v", err)
	}
	if source != specialistsConfigSourceEmbedded {
		t.Fatalf("expected source %s, got %s", specialistsConfigSourceEmbedded, source)
	}
	if cfg == nil {
		t.Fatalf("expected config, got nil")
	}
	if len(cfg.Detectors.PromptInjection) != 3 {
		t.Fatalf("expected 3 prompt_injection detectors, got %d", len(cfg.Detectors.PromptInjection))
	}
	if len(cfg.Detectors.Jailbreak) != 2 {
		t.Fatalf("expected 2 jailbreak detectors, got %d", len(cfg.Detectors.Jailbreak))
	}
	assertDetectorIDs(t, cfg.Detectors.PromptInjection, []string{"prompt_injection_deberta_v3", "prompt_injection_vijil", "prompt_injection_hedgehog"})
	assertDetectorIDs(t, cfg.Detectors.Jailbreak, []string{"jailbreak_jackhhao", "jailbreak2xl"})
	assertDetectorEnabled(t, cfg.Detectors.PromptInjection, "prompt_injection_deberta_v3", true)
	assertDetectorEnabled(t, cfg.Detectors.PromptInjection, "prompt_injection_vijil", true)
	assertDetectorEnabled(t, cfg.Detectors.PromptInjection, "prompt_injection_hedgehog", true)
	assertDetectorEnabled(t, cfg.Detectors.Jailbreak, "jailbreak_jackhhao", true)
	assertDetectorEnabled(t, cfg.Detectors.Jailbreak, "jailbreak2xl", true)
	assertAttackIdx(t, cfg.Detectors.PromptInjection, "prompt_injection_vijil", 1)
	assertAttackIdx(t, cfg.Detectors.Jailbreak, "jailbreak_jackhhao", 1)
}

func TestLoadSpecialistsConfigOverrideFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "specialists.yaml")
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "strajaguard_specialists.yaml"))
	if err != nil {
		t.Fatalf("read base config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, source, err := loadSpecialistsConfigWithFallback(path)
	if err != nil {
		t.Fatalf("load specialists config override: %v", err)
	}
	if source != specialistsConfigSourceFile+":"+path {
		t.Fatalf("expected source %s, got %s", specialistsConfigSourceFile+":"+path, source)
	}
	if cfg == nil {
		t.Fatalf("expected config, got nil")
	}
	if len(cfg.Detectors.PromptInjection) != 3 {
		t.Fatalf("expected 3 prompt_injection detectors, got %d", len(cfg.Detectors.PromptInjection))
	}
	if len(cfg.Detectors.Jailbreak) != 2 {
		t.Fatalf("expected 2 jailbreak detectors, got %d", len(cfg.Detectors.Jailbreak))
	}
	assertDetectorIDs(t, cfg.Detectors.PromptInjection, []string{"prompt_injection_deberta_v3", "prompt_injection_vijil", "prompt_injection_hedgehog"})
	assertDetectorIDs(t, cfg.Detectors.Jailbreak, []string{"jailbreak_jackhhao", "jailbreak2xl"})
	assertDetectorEnabled(t, cfg.Detectors.PromptInjection, "prompt_injection_deberta_v3", false)
	assertDetectorEnabled(t, cfg.Detectors.PromptInjection, "prompt_injection_vijil", true)
	assertDetectorEnabled(t, cfg.Detectors.PromptInjection, "prompt_injection_hedgehog", false)
	assertDetectorEnabled(t, cfg.Detectors.Jailbreak, "jailbreak_jackhhao", false)
	assertDetectorEnabled(t, cfg.Detectors.Jailbreak, "jailbreak2xl", true)
	assertAttackIdx(t, cfg.Detectors.PromptInjection, "prompt_injection_vijil", 1)
	assertAttackIdx(t, cfg.Detectors.Jailbreak, "jailbreak_jackhhao", 1)
}

func TestDetectorEnabled(t *testing.T) {
	enabled := true
	disabled := false
	cases := []struct {
		name string
		spec DetectorSpec
		want bool
	}{
		{name: "nil defaults true", spec: DetectorSpec{ID: "a", Enabled: nil}, want: true},
		{name: "explicit true", spec: DetectorSpec{ID: "b", Enabled: &enabled}, want: true},
		{name: "explicit false", spec: DetectorSpec{ID: "c", Enabled: &disabled}, want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := detectorEnabled(tc.spec)
			if got != tc.want {
				t.Fatalf("detectorEnabled(%s) = %v, want %v", tc.spec.ID, got, tc.want)
			}
		})
	}
}

func TestSpecialistEnabled(t *testing.T) {
	enabled := true
	disabled := false
	cases := []struct {
		name string
		spec SpecialistConfig
		want bool
	}{
		{name: "nil defaults true", spec: SpecialistConfig{Kind: "token_classification", Enabled: nil}, want: true},
		{name: "explicit true", spec: SpecialistConfig{Kind: "token_classification", Enabled: &enabled}, want: true},
		{name: "explicit false", spec: SpecialistConfig{Kind: "token_classification", Enabled: &disabled}, want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := specialistEnabled(tc.spec)
			if got != tc.want {
				t.Fatalf("specialistEnabled = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNormalizeDetectorConfig_DisabledPIINER(t *testing.T) {
	disabled := false
	cfg := &SpecialistsConfig{
		Detectors: SpecialistsDetectorsConfig{
			PromptInjection: []DetectorSpec{
				{
					ID:           "prompt_injection_vijil",
					Kind:         "sequence_classification",
					ModelRef:     "prompt_injection_vijil/model.onnx",
					TokenizerDir: "prompt_injection_vijil/",
					MaxTokens:    256,
				},
			},
		},
		Specialists: map[string]SpecialistConfig{
			"pii_ner": {
				Kind:         "token_classification",
				Onnx:         "pii_ner/model.onnx",
				TokenizerDir: "pii_ner/",
				Enabled:      &disabled,
			},
		},
	}
	_, _, pii, _, _ := normalizeDetectorConfig(cfg)
	if pii != nil {
		t.Fatalf("expected pii_ner to be skipped when enabled=false")
	}
}

func TestLoadSpecialistsConfigExplicitDisabledDetector(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "specialists.yaml")
	data := `
detectors:
  prompt_injection:
    - id: prompt_injection_deberta_v3
      enabled: false
      kind: sequence_classification
      model_ref: prompt_injection_deberta_v3/model.onnx
      tokenizer_dir: prompt_injection_deberta_v3/
      max_tokens: 256
ensemble:
  prompt_injection:
    method: any
    threshold: 0.8
specialists: {}
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := LoadSpecialistsConfig(path)
	if err != nil {
		t.Fatalf("load specialists config: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected config, got nil")
	}
	if len(cfg.Detectors.PromptInjection) != 1 {
		t.Fatalf("expected 1 prompt_injection detector, got %d", len(cfg.Detectors.PromptInjection))
	}
	d := cfg.Detectors.PromptInjection[0]
	if strings.TrimSpace(d.ID) != "prompt_injection_deberta_v3" {
		t.Fatalf("unexpected detector id: %q", d.ID)
	}
	if detectorEnabled(d) {
		t.Fatalf("expected detector %q to be disabled", d.ID)
	}
}

func assertDetectorIDs(t *testing.T, detectors []DetectorSpec, expected []string) {
	t.Helper()
	got := map[string]bool{}
	for _, d := range detectors {
		got[strings.TrimSpace(d.ID)] = true
	}
	for _, id := range expected {
		if !got[id] {
			t.Fatalf("expected detector id %q not found (got=%v)", id, got)
		}
	}
}

func assertAttackIdx(t *testing.T, detectors []DetectorSpec, id string, want int) {
	t.Helper()
	for _, d := range detectors {
		if strings.TrimSpace(d.ID) != id {
			continue
		}
		if d.AttackIdx == nil || *d.AttackIdx != want {
			t.Fatalf("detector %q attack_idx: got=%v want=%d", id, d.AttackIdx, want)
		}
		return
	}
	t.Fatalf("detector %q not found", id)
}

func assertDetectorEnabled(t *testing.T, detectors []DetectorSpec, id string, want bool) {
	t.Helper()
	for _, d := range detectors {
		if strings.TrimSpace(d.ID) != id {
			continue
		}
		if d.Enabled == nil {
			t.Fatalf("detector %q enabled not set explicitly in config", id)
		}
		got := detectorEnabled(d)
		if got != want {
			t.Fatalf("detector %q enabled: got=%v want=%v", id, got, want)
		}
		return
	}
	t.Fatalf("detector %q not found", id)
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
	engine, _, err := LoadSpecialistsEngine(bundleDir, 64, rt, "configs/strajaguard_specialists.yaml")
	if err != nil {
		t.Fatalf("load specialists engine: %v", err)
	}
	for _, eng := range engine.categories {
		for _, det := range eng.detectors {
			switch d := det.(type) {
			case *sequenceDetector:
				if d.m.poolSize != 1 || cap(d.m.sessions) != 1 {
					t.Fatalf("expected single session for %s, got pool_size=%d cap=%d", d.m.id, d.m.poolSize, cap(d.m.sessions))
				}
			case *qwenNextTokenDetector:
				if cap(d.sessions) != 1 {
					t.Fatalf("expected single session for %s, got cap=%d", d.id, cap(d.sessions))
				}
			}
		}
	}
	if engine.piiNER == nil {
		t.Fatalf("expected pii_ner model loaded")
	}
	if engine.piiNER.poolSize != 1 || cap(engine.piiNER.sessions) != 1 {
		t.Fatalf("expected single session for pii_ner, got pool_size=%d cap=%d", engine.piiNER.poolSize, cap(engine.piiNER.sessions))
	}
	if _, err := engine.AnalyzeText(context.Background(), "hello"); err != nil {
		t.Fatalf("analyze text: %v", err)
	}
	if _, err := engine.AnalyzeText(context.Background(), "hello again"); err != nil {
		t.Fatalf("analyze text second pass: %v", err)
	}
	for _, eng := range engine.categories {
		for _, det := range eng.detectors {
			switch d := det.(type) {
			case *sequenceDetector:
				if len(d.m.sessions) != d.m.poolSize {
					t.Fatalf("expected sessions returned for %s, got %d/%d", d.m.id, len(d.m.sessions), d.m.poolSize)
				}
			case *qwenNextTokenDetector:
				if len(d.sessions) != cap(d.sessions) {
					t.Fatalf("expected sessions returned for %s, got %d/%d", d.id, len(d.sessions), cap(d.sessions))
				}
			}
		}
	}
	if len(engine.piiNER.sessions) != engine.piiNER.poolSize {
		t.Fatalf("expected sessions returned for pii_ner, got %d/%d", len(engine.piiNER.sessions), engine.piiNER.poolSize)
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
