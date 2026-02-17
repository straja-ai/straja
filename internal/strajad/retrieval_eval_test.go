package strajad

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetrievalEvalHarnessStages(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "vault.enc")
	store := newVaultStore(storePath, "", retrievalConfig{
		maxSnippetChars: 512,
		maxReadCoverage: 0.75,
		cacheTTL:        30 * time.Second,
		embedder:        nil,
		indexMeta:       defaultRetrievalIndexMeta(nil, nil, "lsh.ann.v1"),
	})
	if _, err := store.Unlock("eval-passphrase", ""); err != nil {
		t.Fatalf("unlock store: %v", err)
	}
	defer func() {
		_ = store.Lock()
	}()

	seedDocs := []struct {
		key        string
		collection string
		title      string
		content    string
	}{
		{
			key:        "doc_sync",
			collection: "work",
			title:      "Migration Playbook",
			content:    "Synchronization migration checklist for service cutover and validation.",
		},
		{
			key:        "doc_mail",
			collection: "work",
			title:      "Incident Mail Thread",
			content:    "From: ops@example.com\nSubject: Customer incident response playbook\nDate: 2026-01-05\n\nEscalate incident and communicate mitigation plan.",
		},
		{
			key:        "doc_repo",
			collection: "work",
			title:      "server.go",
			content:    "package main\n\nfunc BuildLaunchChecklist() string {\n return \"Q2 launch checklist and rollout communication\"\n}\n",
		},
		{
			key:        "doc_noise",
			collection: "work",
			title:      "General Notes",
			content:    "Assorted project updates and unrelated housekeeping items.",
		},
	}
	ids := map[string]string{}
	for _, doc := range seedDocs {
		obj, _, err := store.Write("", doc.collection, doc.title, doc.content)
		if err != nil {
			t.Fatalf("write seed doc %s: %v", doc.key, err)
		}
		ids[doc.key] = obj.ID
	}

	queries := []retrievalEvalQuery{
		{
			Query:             "synchronisation migrate checklists",
			Collection:        "work",
			RelevantObjectIDs: []string{ids["doc_sync"]},
		},
		{
			Query:             "customer incident response playbook",
			Collection:        "work",
			RelevantObjectIDs: []string{ids["doc_mail"]},
		},
		{
			Query:             "q2 launch communication checklist function",
			Collection:        "work",
			RelevantObjectIDs: []string{ids["doc_repo"]},
		},
	}

	store.mu.Lock()
	report := store.evaluateRetrievalLocked(queries, 3)
	store.mu.Unlock()

	if report.QueryCount != len(queries) {
		t.Fatalf("expected query count %d, got %d", len(queries), report.QueryCount)
	}
	if report.Hybrid.RecallAtK < report.Lexical.RecallAtK {
		t.Fatalf("expected hybrid recall >= lexical recall, got hybrid=%.4f lexical=%.4f", report.Hybrid.RecallAtK, report.Lexical.RecallAtK)
	}
	if report.Reranked.PrecisionAtK < report.Hybrid.PrecisionAtK {
		t.Fatalf("expected reranked precision >= hybrid precision, got reranked=%.4f hybrid=%.4f", report.Reranked.PrecisionAtK, report.Hybrid.PrecisionAtK)
	}
}

func TestStructureAwareChunkingSetsSectionMetadata(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "vault.enc")
	store := newVaultStore(storePath, "", retrievalConfig{
		maxSnippetChars: 512,
		maxReadCoverage: 0.75,
		cacheTTL:        30 * time.Second,
		embedder:        nil,
		indexMeta:       defaultRetrievalIndexMeta(nil, nil, "lsh.ann.v1"),
	})
	if _, err := store.Unlock("chunk-passphrase", ""); err != nil {
		t.Fatalf("unlock store: %v", err)
	}
	defer func() {
		_ = store.Lock()
	}()

	content := "From: analyst@example.com\nSubject: Budget notes\n\nAction items for Q2.\n\nFrom: manager@example.com\nSubject: Follow up\n\nPlease confirm milestones."
	obj, _, err := store.Write("", "work", "thread.eml", content)
	if err != nil {
		t.Fatalf("write email thread: %v", err)
	}

	store.mu.RLock()
	chunkIDs := append([]string(nil), store.objectChunkIDs[obj.ID]...)
	store.mu.RUnlock()
	if len(chunkIDs) == 0 {
		t.Fatalf("expected semantic chunks for object %s", obj.ID)
	}

	store.mu.RLock()
	defer store.mu.RUnlock()
	for _, chunkID := range chunkIDs {
		chunk, ok := store.semanticChunks[chunkID]
		if !ok {
			t.Fatalf("missing semantic chunk %s", chunkID)
		}
		if chunk.SectionID == "" {
			t.Fatalf("expected non-empty section id for chunk %s", chunkID)
		}
		if chunk.StartChar >= chunk.EndChar {
			t.Fatalf("expected valid offsets for chunk %s, got %d..%d", chunkID, chunk.StartChar, chunk.EndChar)
		}
	}
}

func TestModelRerankerInfluencesOrdering(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "vault.enc")
	store := newVaultStore(storePath, "", retrievalConfig{
		maxSnippetChars: 512,
		maxReadCoverage: 0.75,
		cacheTTL:        30 * time.Second,
		embedder:        nil,
		reranker:        &stubMarkerReranker{},
		indexMeta:       defaultRetrievalIndexMeta(nil, &stubMarkerReranker{}, "lsh.ann.v1"),
	})
	if _, err := store.Unlock("reranker-passphrase", ""); err != nil {
		t.Fatalf("unlock store: %v", err)
	}
	defer func() {
		_ = store.Lock()
	}()

	plain, _, err := store.Write("", "work", "Plain candidate", "alpha beta general note for retrieval")
	if err != nil {
		t.Fatalf("write plain candidate: %v", err)
	}
	preferred, _, err := store.Write("", "work", "Preferred candidate", "alpha beta preferred-marker note for retrieval")
	if err != nil {
		t.Fatalf("write preferred candidate: %v", err)
	}
	if plain.ID == preferred.ID {
		t.Fatalf("expected unique ids")
	}

	hits, err := store.SearchExpanded("alpha beta", 2, "work", defaultQueryExpansion("alpha beta", "work"))
	if err != nil {
		t.Fatalf("search expanded: %v", err)
	}
	if len(hits) == 0 {
		t.Fatalf("expected search hits")
	}
	if hits[0].ID != preferred.ID {
		t.Fatalf("expected reranker to promote preferred doc %q, got %q", preferred.ID, hits[0].ID)
	}
}

func TestNegativeTermsFilterSuppressesWrongCluster(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "vault.enc")
	store := newVaultStore(storePath, "", retrievalConfig{
		maxSnippetChars: 512,
		maxReadCoverage: 0.75,
		cacheTTL:        30 * time.Second,
		indexMeta:       defaultRetrievalIndexMeta(nil, nil, "lsh.ann.v1"),
	})
	if _, err := store.Unlock("neg-terms-pass", ""); err != nil {
		t.Fatalf("unlock store: %v", err)
	}
	defer func() { _ = store.Lock() }()

	humanDoc, _, err := store.Write("", "work", "Vision notes", "Eyesight is the ability to see clearly and maintain visual focus.")
	if err != nil {
		t.Fatalf("write human doc: %v", err)
	}
	_, _, err = store.Write("", "work", "Subaru manual", "Subaru eyesight system settings for lane departure and cruise controls.")
	if err != nil {
		t.Fatalf("write subaru doc: %v", err)
	}

	expansion := defaultQueryExpansion("eyesight not subaru", "work")
	hits, err := store.SearchExpanded("eyesight not subaru", 3, "work", expansion)
	if err != nil {
		t.Fatalf("search expanded: %v", err)
	}
	if len(hits) == 0 {
		t.Fatalf("expected hits")
	}
	if hits[0].ID != humanDoc.ID {
		t.Fatalf("expected non-subaru doc first, got %q", hits[0].ID)
	}
}

func TestLexicalTitleBoostImprovesRanking(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "vault.enc")
	store := newVaultStore(storePath, "", retrievalConfig{
		maxSnippetChars: 512,
		maxReadCoverage: 0.75,
		cacheTTL:        30 * time.Second,
		indexMeta:       defaultRetrievalIndexMeta(nil, nil, "lsh.ann.v1"),
	})
	if _, err := store.Unlock("title-boost-pass", ""); err != nil {
		t.Fatalf("unlock store: %v", err)
	}
	defer func() { _ = store.Lock() }()

	titleBoosted, _, err := store.Write("", "work", "Eyesight Glossary", "Reference guide with definitions for drivers.")
	if err != nil {
		t.Fatalf("write title boosted: %v", err)
	}
	_, _, err = store.Write("", "work", "Random notes", "This note mentions eyesight once but not glossary details.")
	if err != nil {
		t.Fatalf("write competitor: %v", err)
	}

	store.mu.RLock()
	rows := store.lexicalChunkCandidatesLocked("eyesight glossary", "work", 8)
	store.mu.RUnlock()
	if len(rows) == 0 {
		t.Fatalf("expected lexical chunk candidates")
	}
	if rows[0].ObjectID != titleBoosted.ID {
		t.Fatalf("expected title boosted object first in lexical stage, got %q", rows[0].ObjectID)
	}
}

type stubMarkerReranker struct{}

func (s *stubMarkerReranker) ID() string {
	return "stub.marker.reranker.v1"
}

func (s *stubMarkerReranker) Score(_ context.Context, _ string, docs []string) ([]float64, error) {
	out := make([]float64, len(docs))
	for i, doc := range docs {
		if strings.Contains(strings.ToLower(doc), "preferred-marker") {
			out[i] = 1
			continue
		}
		out[i] = 0.05
	}
	return out, nil
}
