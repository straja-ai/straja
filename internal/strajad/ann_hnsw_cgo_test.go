//go:build cgo

package strajad

import (
	"fmt"
	"testing"
)

func TestHNSWANNEngineQuery_HighLimitDoesNotFail(t *testing.T) {
	engine := newHNSWANNEngine(retrievalConfig{
		hnswM:              32,
		hnswEfConstruction: 200,
		hnswEfSearch:       128,
		hnswMaxElements:    1024,
	}).(*hnswANNEngine)
	defer engine.Close()

	for i := 0; i < 24; i++ {
		vec := make([]float32, semanticEmbeddingDims)
		for d := range vec {
			vec[d] = float32((i + d + 1) % 11)
		}
		if err := engine.Upsert(fmt.Sprintf("chunk_%03d", i), vec); err != nil {
			t.Fatalf("upsert failed: %v", err)
		}
	}

	query := make([]float32, semanticEmbeddingDims)
	for d := range query {
		query[d] = float32((d + 3) % 11)
	}

	ids, err := engine.Query(query, 800)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(ids) == 0 {
		t.Fatalf("expected query results")
	}
	if len(ids) > 24 {
		t.Fatalf("expected at most 24 ids, got %d", len(ids))
	}
}

func TestHNSWANNEngineQuery_ClampsByEfSearch(t *testing.T) {
	engine := newHNSWANNEngine(retrievalConfig{
		hnswM:              16,
		hnswEfConstruction: 64,
		hnswEfSearch:       4,
		hnswMaxElements:    512,
	}).(*hnswANNEngine)
	defer engine.Close()

	for i := 0; i < 12; i++ {
		vec := make([]float32, semanticEmbeddingDims)
		for d := range vec {
			vec[d] = float32((i*3 + d + 5) % 13)
		}
		if err := engine.Upsert(fmt.Sprintf("doc_%03d", i), vec); err != nil {
			t.Fatalf("upsert failed: %v", err)
		}
	}

	query := make([]float32, semanticEmbeddingDims)
	for d := range query {
		query[d] = float32((d + 1) % 13)
	}

	ids, err := engine.Query(query, 128)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(ids) > 4 {
		t.Fatalf("expected efSearch clamp to 4 results, got %d", len(ids))
	}
}

