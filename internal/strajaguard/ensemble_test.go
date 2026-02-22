package strajaguard

import (
	"context"
	"testing"
	"time"

	"github.com/straja-ai/straja-gateway/internal/safety"
)

type fakeDetector struct {
	id    string
	score *float32
	err   string
	sleep time.Duration
}

func (f fakeDetector) Evaluate(ctx context.Context, normalizedText string) safety.DetectorResult {
	if f.sleep > 0 {
		time.Sleep(f.sleep)
	}
	out := safety.DetectorResult{ID: f.id, Kind: "fake"}
	if f.err != "" {
		out.Error = f.err
		return out
	}
	out.Score = f.score
	return out
}

func f32(v float32) *float32 { return &v }

func TestEnsembleAny_MaxAndThreshold(t *testing.T) {
	eng := &categoryEngine{
		category:  "jailbreak",
		method:    "any",
		threshold: 0.8,
		detectors: []Detector{
			fakeDetector{id: "a", score: f32(0.2)},
			fakeDetector{id: "b", score: f32(0.9)},
		},
	}
	got := eng.evaluate(context.Background(), "x")
	if got.Ensemble.Score != 0.9 {
		t.Fatalf("expected max score 0.9, got %.4f", got.Ensemble.Score)
	}
	if !got.Ensemble.Attack {
		t.Fatalf("expected attack=true")
	}
	if got.Ensemble.ValidDetectors != 2 || got.Ensemble.TotalDetectors != 2 {
		t.Fatalf("unexpected detector counts: %+v", got.Ensemble)
	}
}

func TestEnsembleMean_MeanAndThreshold(t *testing.T) {
	eng := &categoryEngine{
		category:  "prompt_injection",
		method:    "mean",
		threshold: 0.6,
		detectors: []Detector{
			fakeDetector{id: "a", score: f32(0.4)},
			fakeDetector{id: "b", score: f32(0.8)},
		},
	}
	got := eng.evaluate(context.Background(), "x")
	if got.Ensemble.Score != 0.6 {
		t.Fatalf("expected mean score 0.6, got %.4f", got.Ensemble.Score)
	}
	if !got.Ensemble.Attack {
		t.Fatalf("expected attack=true")
	}
}

func TestEnsembleErrorsExcluded(t *testing.T) {
	eng := &categoryEngine{
		category:  "jailbreak",
		method:    "any",
		threshold: 0.8,
		detectors: []Detector{
			fakeDetector{id: "a", err: "boom"},
			fakeDetector{id: "b", score: f32(0.7)},
		},
	}
	got := eng.evaluate(context.Background(), "x")
	if got.Ensemble.Score != 0.7 {
		t.Fatalf("expected score 0.7, got %.4f", got.Ensemble.Score)
	}
	if got.Ensemble.Attack {
		t.Fatalf("expected attack=false")
	}
	if got.Ensemble.ValidDetectors != 1 || got.Ensemble.TotalDetectors != 2 {
		t.Fatalf("unexpected detector counts: %+v", got.Ensemble)
	}
}

func TestEnsembleAllFailed_FailOpen(t *testing.T) {
	eng := &categoryEngine{
		category:  "jailbreak",
		method:    "any",
		threshold: 0.8,
		detectors: []Detector{
			fakeDetector{id: "b", err: "fail"},
			fakeDetector{id: "a", err: "fail"},
		},
	}
	got := eng.evaluate(context.Background(), "x")
	if got.Ensemble.Status != "all_detectors_failed" {
		t.Fatalf("expected status all_detectors_failed, got %s", got.Ensemble.Status)
	}
	if got.Ensemble.Score != 0 || got.Ensemble.Attack {
		t.Fatalf("expected fail-open score=0 attack=false, got score=%.4f attack=%v", got.Ensemble.Score, got.Ensemble.Attack)
	}
}

func TestEnsembleDisabled(t *testing.T) {
	eng := &categoryEngine{
		category:  "jailbreak",
		method:    "any",
		threshold: 0.8,
		detectors: nil,
	}
	got := eng.evaluate(context.Background(), "x")
	if got.Ensemble.Status != "disabled" {
		t.Fatalf("expected status disabled, got %s", got.Ensemble.Status)
	}
	if got.Ensemble.Score != 0 || got.Ensemble.Attack {
		t.Fatalf("expected score=0 attack=false, got score=%.4f attack=%v", got.Ensemble.Score, got.Ensemble.Attack)
	}
}

func TestEnsembleSortsByID(t *testing.T) {
	eng := &categoryEngine{
		category:  "jailbreak",
		method:    "any",
		threshold: 0.1,
		detectors: []Detector{
			fakeDetector{id: "b", score: f32(0.1)},
			fakeDetector{id: "a", score: f32(0.1)},
		},
	}
	got := eng.evaluate(context.Background(), "x")
	if len(got.Detectors) != 2 {
		t.Fatalf("expected 2 detectors, got %d", len(got.Detectors))
	}
	if got.Detectors[0].ID != "a" || got.Detectors[1].ID != "b" {
		t.Fatalf("expected sorted ids [a b], got [%s %s]", got.Detectors[0].ID, got.Detectors[1].ID)
	}
}

func TestEnsembleConcurrency(t *testing.T) {
	eng := &categoryEngine{
		category:  "jailbreak",
		method:    "any",
		threshold: 0.1,
		detectors: []Detector{
			fakeDetector{id: "a", score: f32(0.2), sleep: 50 * time.Millisecond},
			fakeDetector{id: "b", score: f32(0.2), sleep: 50 * time.Millisecond},
		},
	}
	start := time.Now()
	_ = eng.evaluate(context.Background(), "x")
	elapsed := time.Since(start)

	// Sequential would be ~100ms; concurrent should be closer to ~50ms.
	if elapsed > 90*time.Millisecond {
		t.Fatalf("expected concurrent execution, elapsed=%s", elapsed)
	}
}

func TestEnsembleMedian_TwoDetectorsAveragesMiddle(t *testing.T) {
	eng := &categoryEngine{
		category:  "jailbreak",
		method:    "median",
		threshold: 0.8,
		detectors: []Detector{
			fakeDetector{id: "a", score: f32(0.1)},
			fakeDetector{id: "b", score: f32(0.9)},
		},
	}
	got := eng.evaluate(context.Background(), "x")
	if got.Ensemble.Score != 0.5 {
		t.Fatalf("expected median score 0.5, got %.4f", got.Ensemble.Score)
	}
	if got.Ensemble.Attack {
		t.Fatalf("expected attack=false")
	}
}
