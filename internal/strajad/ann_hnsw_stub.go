//go:build !cgo

package strajad

type noopANNEngine struct{}

func newHNSWANNEngine(cfg retrievalConfig) annEngine {
	return nil
}

func (n *noopANNEngine) Name() string                                     { return "noop.ann.v1" }
func (n *noopANNEngine) Reset(dim int, capacity int) error                { return nil }
func (n *noopANNEngine) Upsert(chunkID string, vec []float32) error       { return nil }
func (n *noopANNEngine) Delete(chunkID string) error                      { return nil }
func (n *noopANNEngine) Query(vec []float32, limit int) ([]string, error) { return nil, nil }
func (n *noopANNEngine) Snapshot(path string) error                       { return nil }
func (n *noopANNEngine) Restore(path string, dim int, capacity int, chunkIDs []string) error {
	return nil
}
func (n *noopANNEngine) Close() {}
