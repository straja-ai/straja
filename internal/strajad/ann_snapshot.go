package strajad

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type annSnapshotMeta struct {
	Version     int       `json:"version"`
	Provider    string    `json:"provider"`
	ANNVersion  string    `json:"ann_version"`
	ChunkCount  int       `json:"chunk_count"`
	ChunkDigest string    `json:"chunk_digest"`
	Dim         int       `json:"dim"`
	SavedAt     time.Time `json:"saved_at"`
}

func (s *vaultStore) annSnapshotPath() string {
	base := strings.TrimSpace(s.path)
	if base == "" {
		return ""
	}
	return base + ".ann.hnsw"
}

func (s *vaultStore) annSnapshotMetaPath() string {
	base := strings.TrimSpace(s.path)
	if base == "" {
		return ""
	}
	return base + ".ann.hnsw.meta.json"
}

func (s *vaultStore) persistANNSnapshotLocked() error {
	if s == nil || s.annEngine == nil || s.state == nil {
		return nil
	}
	snapshotPath := s.annSnapshotPath()
	metaPath := s.annSnapshotMetaPath()
	if snapshotPath == "" || metaPath == "" {
		return nil
	}
	if len(s.semanticChunks) == 0 {
		_ = os.Remove(snapshotPath)
		_ = os.Remove(metaPath)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(snapshotPath), 0o755); err != nil {
		return err
	}
	if err := s.annEngine.Snapshot(snapshotPath); err != nil {
		return err
	}
	meta := annSnapshotMeta{
		Version:     1,
		Provider:    strings.TrimSpace(strings.ToLower(s.retrieval.annProvider)),
		ANNVersion:  s.retrieval.indexMeta.ANNVersion,
		ChunkCount:  len(s.semanticChunks),
		ChunkDigest: s.semanticChunkDigestLocked(),
		Dim:         semanticEmbeddingDims,
		SavedAt:     time.Now().UTC(),
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if err := os.WriteFile(metaPath, encoded, 0o600); err != nil {
		return err
	}
	return nil
}

func (s *vaultStore) restoreANNSnapshotLocked() bool {
	if s == nil || s.annEngine == nil || s.state == nil {
		return false
	}
	snapshotPath := s.annSnapshotPath()
	metaPath := s.annSnapshotMetaPath()
	if snapshotPath == "" || metaPath == "" {
		return false
	}
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return false
	}
	var meta annSnapshotMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return false
	}
	if meta.Version != 1 {
		return false
	}
	if meta.Dim != semanticEmbeddingDims {
		return false
	}
	if meta.ChunkCount != len(s.semanticChunks) {
		return false
	}
	if strings.TrimSpace(meta.ANNVersion) != strings.TrimSpace(s.retrieval.indexMeta.ANNVersion) {
		return false
	}
	if strings.TrimSpace(strings.ToLower(meta.Provider)) != strings.TrimSpace(strings.ToLower(s.retrieval.annProvider)) {
		return false
	}
	if meta.ChunkDigest != s.semanticChunkDigestLocked() {
		return false
	}
	ids := make([]string, 0, len(s.semanticChunks))
	for chunkID := range s.semanticChunks {
		ids = append(ids, chunkID)
	}
	sort.Strings(ids)
	capacity := maxInt(len(ids)*2, s.retrieval.hnswMaxElements)
	if err := s.annEngine.Restore(snapshotPath, semanticEmbeddingDims, capacity, ids); err != nil {
		return false
	}
	return true
}

func (s *vaultStore) semanticChunkDigestLocked() string {
	if s == nil || len(s.semanticChunks) == 0 {
		return ""
	}
	ids := make([]string, 0, len(s.semanticChunks))
	for id := range s.semanticChunks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	h := fnv.New64a()
	for _, id := range ids {
		chunk := s.semanticChunks[id]
		_, _ = h.Write([]byte(id))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(chunk.ObjectID))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(chunk.SectionID))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(strconv.Itoa(chunk.StartChar)))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(strconv.Itoa(chunk.EndChar)))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(strconv.Itoa(len(chunk.Vector))))
		_, _ = h.Write([]byte{0})
		for _, v := range chunk.Vector {
			bits := math.Float32bits(v)
			_, _ = h.Write([]byte{
				byte(bits),
				byte(bits >> 8),
				byte(bits >> 16),
				byte(bits >> 24),
			})
		}
	}
	return fmt.Sprintf("%x", h.Sum64())
}
