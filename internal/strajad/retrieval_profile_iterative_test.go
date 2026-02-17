package strajad

import (
	"context"
	"testing"
)

func TestConfigApplyDefaults_RetrievalProfiles(t *testing.T) {
	cfg := Config{RetrievalProfile: "balanced"}
	cfg.applyDefaults()
	if cfg.RetrievalProfile != "balanced" {
		t.Fatalf("expected balanced profile, got %q", cfg.RetrievalProfile)
	}
	if cfg.RetrievalExpandedQueries != 4 || cfg.RetrievalLexicalTopN != 120 || cfg.RetrievalDenseTopN != 120 {
		t.Fatalf("unexpected balanced profile retrieval depth: %+v", cfg)
	}
	if cfg.RetrievalIterativePasses != 1 || cfg.RetrievalSecondPassAddN != 8 {
		t.Fatalf("unexpected balanced iterative defaults: passes=%d add=%d", cfg.RetrievalIterativePasses, cfg.RetrievalSecondPassAddN)
	}

	cfg = Config{RetrievalProfile: "low_resource"}
	cfg.applyDefaults()
	if cfg.RetrievalExpandedQueries != 3 || cfg.RetrievalLexicalTopN != 60 || cfg.RetrievalDenseTopN != 60 {
		t.Fatalf("unexpected low_resource profile retrieval depth: %+v", cfg)
	}
	if cfg.RetrievalIterativePasses != 1 || cfg.RetrievalSecondPassAddN != 5 {
		t.Fatalf("unexpected low_resource iterative defaults: passes=%d add=%d", cfg.RetrievalIterativePasses, cfg.RetrievalSecondPassAddN)
	}
}

func TestSearchExpandedWithIterativePasses_EmitsCoverageNote(t *testing.T) {
	d := newTestDaemon(t)
	mustUnlock(t, d, "iterative-search-pass", "")

	_, _, err := d.store.Write("", "work", "Subaru eyesight manual.pdf",
		"Manual cancellation by driver using SET/RES switch and indicator behavior.")
	if err != nil {
		t.Fatalf("seed write 1: %v", err)
	}
	_, _, err = d.store.Write("", "work", "Subaru eyesight warnings.pdf",
		"EyeSight may temporarily stop automatically in poor visibility or camera obstruction conditions.")
	if err != nil {
		t.Fatalf("seed write 2: %v", err)
	}

	query := "can eyesight be disabled by the driver and in which conditions can it automatically turn off?"
	expansion := d.expandRetrievalQuery(context.Background(), query, "work")
	hits, note, err := d.searchExpandedWithIterativePasses(context.Background(), query, "work", 5, expansion)
	if err != nil {
		t.Fatalf("iterative search failed: %v", err)
	}
	if len(hits) == 0 {
		t.Fatalf("expected iterative search hits")
	}
	if note.PassesUsed < 2 {
		t.Fatalf("expected iterative passes to run, got %d", note.PassesUsed)
	}
	if len(note.FollowupQueries) == 0 {
		t.Fatalf("expected followup queries in coverage note")
	}
}
