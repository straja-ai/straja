package strajad

import "strings"

type annEngine interface {
	Name() string
	Reset(dim int, capacity int) error
	Upsert(chunkID string, vec []float32) error
	Delete(chunkID string) error
	Query(vec []float32, limit int) ([]string, error)
	Snapshot(path string) error
	Restore(path string, dim int, capacity int, chunkIDs []string) error
	Close()
}

func resolveANNVersion(provider string, engine annEngine) string {
	if engine != nil {
		name := strings.TrimSpace(engine.Name())
		if name != "" {
			return name
		}
	}
	return "lsh.ann.v1"
}

func newANNEngine(cfg retrievalConfig) annEngine {
	switch strings.TrimSpace(strings.ToLower(cfg.annProvider)) {
	case "hnswlib":
		return newHNSWANNEngine(cfg)
	default:
		return nil
	}
}
