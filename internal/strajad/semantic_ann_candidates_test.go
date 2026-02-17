package strajad

import "testing"

type stubANNEngine struct {
	ids []string
}

func (s *stubANNEngine) Name() string { return "stub.ann" }
func (s *stubANNEngine) Reset(dim int, capacity int) error {
	return nil
}
func (s *stubANNEngine) Upsert(chunkID string, vec []float32) error { return nil }
func (s *stubANNEngine) Delete(chunkID string) error                { return nil }
func (s *stubANNEngine) Query(vec []float32, limit int) ([]string, error) {
	if limit <= 0 || len(s.ids) == 0 {
		return nil, nil
	}
	out := append([]string(nil), s.ids...)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (s *stubANNEngine) Close()                     {}
func (s *stubANNEngine) Snapshot(path string) error { return nil }
func (s *stubANNEngine) Restore(path string, dim, cap int, ids []string) error {
	return nil
}

func TestANNCandidateChunkIDs_MergesEngineAndBucketFallback(t *testing.T) {
	q := make([]float32, semanticEmbeddingDims)
	q[0] = 1

	s := &vaultStore{
		annEngine:    &stubANNEngine{ids: []string{"ann_1"}},
		annBuckets:   map[uint64][]string{},
		chunkANNKeys: map[string][]uint64{},
	}
	for _, key := range annBucketKeys(q) {
		s.annBuckets[key] = []string{"ann_1", "bucket_1", "bucket_2"}
	}

	out := s.annCandidateChunkIDsLocked(q, 3)
	if len(out) != 3 {
		t.Fatalf("expected 3 merged candidates, got %d: %v", len(out), out)
	}
	if out[0] != "ann_1" {
		t.Fatalf("expected ANN result first, got %v", out)
	}
	seen := map[string]struct{}{}
	for _, id := range out {
		if _, ok := seen[id]; ok {
			t.Fatalf("expected deduped candidate ids, got %v", out)
		}
		seen[id] = struct{}{}
	}
}
