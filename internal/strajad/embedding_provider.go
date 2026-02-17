package strajad

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	embeddingModeDeterministic = "deterministic_hash_v1"
	embeddingModeOllama        = "ollama_embed_v1"
)

type embeddingProvider interface {
	ID() string
	Embed(ctx context.Context, text string) ([]float32, error)
}

type ollamaEmbeddingProvider struct {
	endpoint string
	model    string
	timeout  time.Duration
	client   *http.Client

	mu          sync.Mutex
	lastFailure time.Time
}

func newEmbeddingProvider(cfg Config) embeddingProvider {
	if !cfg.EmbeddingEnabled {
		return nil
	}
	provider := strings.TrimSpace(strings.ToLower(cfg.EmbeddingProvider))
	switch provider {
	case "", "ollama":
		endpoint := strings.TrimSpace(cfg.EmbeddingEndpoint)
		if endpoint == "" {
			endpoint = strings.TrimSpace(cfg.BrokerEndpoint)
		}
		model := strings.TrimSpace(cfg.EmbeddingModel)
		if model == "" {
			model = "nomic-embed-text"
		}
		timeout := cfg.EmbeddingTimeout
		if timeout <= 0 {
			timeout = 1400 * time.Millisecond
		}
		return &ollamaEmbeddingProvider{
			endpoint: strings.TrimRight(endpoint, "/"),
			model:    model,
			timeout:  timeout,
			client:   &http.Client{},
		}
	default:
		return nil
	}
}

func (p *ollamaEmbeddingProvider) ID() string {
	if p == nil {
		return embeddingModeDeterministic
	}
	return embeddingModeOllama + ":" + strings.TrimSpace(p.model)
}

func (p *ollamaEmbeddingProvider) Embed(ctx context.Context, text string) ([]float32, error) {
	if p == nil {
		return nil, errors.New("embedding provider is nil")
	}
	text = truncateUTF8ByBytes(normalizeSpacing(text), 12000)
	if text == "" {
		return nil, errors.New("empty embedding text")
	}
	if !p.allowRequestNow() {
		return nil, errors.New("embedding provider cooling down after failures")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	reqCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	vec, err := p.callEmbedV2(reqCtx, text)
	if err == nil && len(vec) > 0 {
		return vec, nil
	}
	vecLegacy, legacyErr := p.callEmbedLegacy(reqCtx, text)
	if legacyErr == nil && len(vecLegacy) > 0 {
		return vecLegacy, nil
	}
	if err == nil {
		err = legacyErr
	}
	p.recordFailure()
	return nil, err
}

func (p *ollamaEmbeddingProvider) allowRequestNow() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastFailure.IsZero() {
		return true
	}
	return time.Since(p.lastFailure) > 20*time.Second
}

func (p *ollamaEmbeddingProvider) recordFailure() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastFailure = time.Now().UTC()
}

func (p *ollamaEmbeddingProvider) callEmbedV2(ctx context.Context, text string) ([]float32, error) {
	payload := map[string]any{
		"model": p.model,
		"input": []string{text},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/api/embed", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status=%d", resp.StatusCode)
	}
	var parsed struct {
		Embeddings [][]float64 `json:"embeddings"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&parsed); err != nil {
		return nil, err
	}
	if len(parsed.Embeddings) == 0 || len(parsed.Embeddings[0]) == 0 {
		return nil, errors.New("empty embeddings")
	}
	return float64To32(parsed.Embeddings[0]), nil
}

func (p *ollamaEmbeddingProvider) callEmbedLegacy(ctx context.Context, text string) ([]float32, error) {
	payload := map[string]any{
		"model":  p.model,
		"prompt": text,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/api/embeddings", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status=%d", resp.StatusCode)
	}
	var parsed struct {
		Embedding []float64 `json:"embedding"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&parsed); err != nil {
		return nil, err
	}
	if len(parsed.Embedding) == 0 {
		return nil, errors.New("empty embedding")
	}
	return float64To32(parsed.Embedding), nil
}

func float64To32(in []float64) []float32 {
	if len(in) == 0 {
		return nil
	}
	out := make([]float32, 0, len(in))
	for _, v := range in {
		out = append(out, float32(v))
	}
	return out
}

func projectEmbedding(raw []float32, dims int) []float32 {
	if dims <= 0 {
		dims = semanticEmbeddingDims
	}
	out := make([]float32, dims)
	if len(raw) == 0 {
		return out
	}
	for i, v := range raw {
		// Stable signed projection keeps ANN dimensions fixed regardless of model.
		sign := float32(1)
		if (i/7)%2 == 1 {
			sign = -1
		}
		out[i%dims] += (v * sign)
	}
	normalizeVector(out)
	return out
}

func defaultRetrievalIndexMeta(embedder embeddingProvider, reranker rerankerProvider, annVersion string) retrievalIndexMeta {
	if strings.TrimSpace(annVersion) == "" {
		annVersion = "lsh.ann.v1"
	}
	meta := retrievalIndexMeta{
		Version:             "vault.retrieval.v3",
		EmbeddingBackend:    embeddingModeDeterministic,
		EmbeddingModel:      embeddingModeDeterministic,
		EmbeddingDim:        semanticEmbeddingDims,
		ChunkingVersion:     "chunking.v2.structure_aware",
		LexicalIndexVersion: "bm25.chunk.v1",
		ANNVersion:          annVersion,
		RerankerVersion:     "cross_signal.v1",
	}
	if embedder != nil {
		meta.EmbeddingBackend = embeddingModeOllama
		meta.EmbeddingModel = embedder.ID()
	}
	if reranker != nil {
		meta.RerankerVersion = reranker.ID()
	}
	return meta
}
