//go:build cgo

package strajad

import (
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/oligo/hnswgo"
)

type hnswANNEngine struct {
	index *hnswgo.HnswIndex
	dim   int

	m              int
	efConstruction int
	efSearch       int
	maxElements    int

	labelsByChunk map[string]uint64
	chunksByLabel map[uint64]string
}

func newHNSWANNEngine(cfg retrievalConfig) annEngine {
	m := cfg.hnswM
	if m <= 0 {
		m = 32
	}
	efConstruction := cfg.hnswEfConstruction
	if efConstruction <= 0 {
		efConstruction = 200
	}
	efSearch := cfg.hnswEfSearch
	if efSearch <= 0 {
		efSearch = 128
	}
	maxElements := cfg.hnswMaxElements
	if maxElements <= 0 {
		maxElements = 200000
	}
	return &hnswANNEngine{
		m:              m,
		efConstruction: efConstruction,
		efSearch:       efSearch,
		maxElements:    maxElements,
		labelsByChunk:  map[string]uint64{},
		chunksByLabel:  map[uint64]string{},
	}
}

func (e *hnswANNEngine) Name() string {
	return fmt.Sprintf("hnswlib.ann.v1:m=%d,efc=%d,efs=%d,max=%d", e.m, e.efConstruction, e.efSearch, e.maxElements)
}

func (e *hnswANNEngine) Reset(dim int, capacity int) error {
	if e == nil {
		return nil
	}
	if dim <= 0 {
		dim = semanticEmbeddingDims
	}
	if e.index != nil {
		e.index.Free()
		e.index = nil
	}
	maxElements := e.maxElements
	if capacity > maxElements {
		maxElements = capacity
	}
	if maxElements < 1024 {
		maxElements = 1024
	}
	e.dim = dim
	e.labelsByChunk = map[string]uint64{}
	e.chunksByLabel = map[uint64]string{}
	e.index = hnswgo.New(dim, e.m, e.efConstruction, 42, uint64(maxElements), hnswgo.Cosine, true)
	if e.index == nil {
		return fmt.Errorf("failed to initialize hnsw index")
	}
	e.index.SetEf(e.efSearch)
	return nil
}

func (e *hnswANNEngine) ensureIndex(dim int) error {
	if e.index != nil {
		return nil
	}
	if dim <= 0 {
		dim = semanticEmbeddingDims
	}
	return e.Reset(dim, e.maxElements)
}

func (e *hnswANNEngine) Upsert(chunkID string, vec []float32) error {
	if e == nil {
		return nil
	}
	chunkID = strings.TrimSpace(chunkID)
	if chunkID == "" || len(vec) == 0 {
		return nil
	}
	if err := e.ensureIndex(len(vec)); err != nil {
		return err
	}
	if len(vec) != e.dim {
		return fmt.Errorf("hnsw dim mismatch: expected %d got %d", e.dim, len(vec))
	}
	label := e.labelForChunk(chunkID)
	current := int(e.index.GetCurrentCount())
	capacity := int(e.index.GetMaxElements())
	if current+2 >= capacity {
		e.index.ResizeIndex(uint64(capacity * 2))
	}
	return e.index.AddPoints([][]float32{vec}, []uint64{label}, 1, true)
}

func (e *hnswANNEngine) Delete(chunkID string) error {
	if e == nil || e.index == nil {
		return nil
	}
	chunkID = strings.TrimSpace(chunkID)
	if chunkID == "" {
		return nil
	}
	label, ok := e.labelsByChunk[chunkID]
	if !ok {
		return nil
	}
	e.index.MarkDeleted(label)
	delete(e.labelsByChunk, chunkID)
	delete(e.chunksByLabel, label)
	return nil
}

func (e *hnswANNEngine) Query(vec []float32, limit int) ([]string, error) {
	if e == nil || e.index == nil {
		return nil, nil
	}
	if len(vec) == 0 || limit <= 0 {
		return nil, nil
	}
	if len(vec) != e.dim {
		return nil, nil
	}
	current := int(e.index.GetCurrentCount())
	if current <= 0 {
		return nil, nil
	}
	// Guard against hnswlib topK failures (e.g. efSearch < topK).
	// We cap by active labels and efSearch before invoking SearchKNN.
	k := safeHNSWTopK(limit, current, len(e.chunksByLabel), e.efSearch)
	if k <= 0 {
		return nil, nil
	}
	// Keep ef at least as large as the requested topK for stability.
	e.index.SetEf(maxInt(e.efSearch, k))

	results, err := e.index.SearchKNN([][]float32{vec}, k, 1)
	if err != nil {
		// Degrade gracefully instead of propagating fatal ANN errors.
		for retryK := k / 2; retryK >= 1; retryK /= 2 {
			results, err = e.index.SearchKNN([][]float32{vec}, retryK, 1)
			if err == nil {
				k = retryK
				break
			}
		}
		if err != nil {
			return nil, nil
		}
	}
	if len(results) == 0 {
		return nil, nil
	}
	out := make([]string, 0, minInt(k, len(results[0])))
	for _, row := range results[0] {
		if row == nil {
			continue
		}
		chunkID, ok := e.chunksByLabel[row.Label]
		if !ok {
			continue
		}
		out = append(out, chunkID)
		if len(out) >= k {
			break
		}
	}
	return out, nil
}

func (e *hnswANNEngine) Close() {
	if e == nil {
		return
	}
	if e.index != nil {
		e.index.Free()
		e.index = nil
	}
	e.labelsByChunk = map[string]uint64{}
	e.chunksByLabel = map[uint64]string{}
}

func (e *hnswANNEngine) labelForChunk(chunkID string) uint64 {
	if label, ok := e.labelsByChunk[chunkID]; ok {
		return label
	}
	label := hashLabel(chunkID)
	e.labelsByChunk[chunkID] = label
	e.chunksByLabel[label] = chunkID
	return label
}

func (e *hnswANNEngine) Snapshot(path string) error {
	if e == nil || e.index == nil {
		return nil
	}
	e.index.Save(path)
	return nil
}

func (e *hnswANNEngine) Restore(path string, dim int, capacity int, chunkIDs []string) error {
	if e == nil {
		return nil
	}
	if e.index != nil {
		e.index.Free()
		e.index = nil
	}
	if dim <= 0 {
		dim = semanticEmbeddingDims
	}
	if capacity <= 0 {
		capacity = e.maxElements
	}
	maxElements := e.maxElements
	if capacity > maxElements {
		maxElements = capacity
	}
	if maxElements < 1024 {
		maxElements = 1024
	}
	e.index = hnswgo.Load(path, hnswgo.Cosine, dim, uint64(maxElements), true)
	if e.index == nil {
		return fmt.Errorf("failed to load hnsw snapshot")
	}
	e.index.SetEf(e.efSearch)
	e.dim = dim
	e.labelsByChunk = map[string]uint64{}
	e.chunksByLabel = map[uint64]string{}
	for _, chunkID := range chunkIDs {
		chunkID = strings.TrimSpace(chunkID)
		if chunkID == "" {
			continue
		}
		label := hashLabel(chunkID)
		e.labelsByChunk[chunkID] = label
		e.chunksByLabel[label] = chunkID
	}
	return nil
}

func hashLabel(v string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(v))
	out := h.Sum64()
	if out == 0 {
		return 1
	}
	return out
}
