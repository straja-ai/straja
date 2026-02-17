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
	rerankerModeOllama = "ollama_reranker_v1"
)

type rerankerProvider interface {
	ID() string
	Score(ctx context.Context, query string, docs []string) ([]float64, error)
}

type ollamaRerankerProvider struct {
	endpoint string
	model    string
	timeout  time.Duration
	batch    int
	client   *http.Client

	mu          sync.Mutex
	lastFailure time.Time
}

func newRerankerProvider(cfg Config) rerankerProvider {
	if !cfg.RerankerEnabled {
		return nil
	}
	provider := strings.TrimSpace(strings.ToLower(cfg.RerankerProvider))
	switch provider {
	case "", "ollama":
		endpoint := strings.TrimSpace(cfg.RerankerEndpoint)
		if endpoint == "" {
			endpoint = strings.TrimSpace(cfg.BrokerEndpoint)
		}
		model := strings.TrimSpace(cfg.RerankerModel)
		if model == "" {
			model = "phi4-mini:3.8b"
		}
		timeout := cfg.RerankerTimeout
		if timeout <= 0 {
			timeout = 1800 * time.Millisecond
		}
		batch := cfg.RerankerBatchSize
		if batch <= 0 {
			batch = 10
		}
		return &ollamaRerankerProvider{
			endpoint: strings.TrimRight(endpoint, "/"),
			model:    model,
			timeout:  timeout,
			batch:    batch,
			client:   &http.Client{},
		}
	default:
		return nil
	}
}

func (p *ollamaRerankerProvider) ID() string {
	if p == nil {
		return "none"
	}
	return rerankerModeOllama + ":" + strings.TrimSpace(p.model)
}

func (p *ollamaRerankerProvider) Score(ctx context.Context, query string, docs []string) ([]float64, error) {
	if p == nil {
		return nil, errors.New("reranker provider is nil")
	}
	query = truncateUTF8ByBytes(normalizeSpacing(query), 2000)
	if query == "" {
		return nil, errors.New("query required")
	}
	if len(docs) == 0 {
		return []float64{}, nil
	}
	if !p.allowRequestNow() {
		return nil, errors.New("reranker cooling down after failures")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	out := make([]float64, len(docs))
	for i := 0; i < len(docs); i += p.batch {
		end := i + p.batch
		if end > len(docs) {
			end = len(docs)
		}
		batchScores, err := p.scoreBatch(ctx, query, docs[i:end])
		if err != nil {
			p.recordFailure()
			return nil, err
		}
		copy(out[i:end], batchScores)
	}
	return out, nil
}

func (p *ollamaRerankerProvider) allowRequestNow() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastFailure.IsZero() {
		return true
	}
	return time.Since(p.lastFailure) > 25*time.Second
}

func (p *ollamaRerankerProvider) recordFailure() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastFailure = time.Now().UTC()
}

func (p *ollamaRerankerProvider) scoreBatch(ctx context.Context, query string, docs []string) ([]float64, error) {
	type item struct {
		ID   int    `json:"id"`
		Text string `json:"text"`
	}
	items := make([]item, 0, len(docs))
	for idx, doc := range docs {
		items = append(items, item{
			ID:   idx,
			Text: truncateUTF8ByBytes(normalizeSpacing(doc), 1800),
		})
	}
	in := map[string]any{
		"query": query,
		"docs":  items,
	}
	inJSON, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}

	prompt := strings.Join([]string{
		"You are a relevance reranker.",
		"Return strict JSON object: {\"scores\":[{\"id\":number,\"score\":number}]}",
		"Each score must be in [0,1], where 1 is highest relevance.",
		"Score each doc independently for the query.",
		"Do not return explanations.",
	}, "\n") + "\n\nInput JSON:\n" + string(inJSON)

	reqBody := map[string]any{
		"model":  p.model,
		"stream": false,
		"format": "json",
		"options": map[string]any{
			"temperature": 0,
		},
		"prompt": prompt,
	}
	rawReq, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, p.endpoint+"/api/generate", bytes.NewReader(rawReq))
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
	var payload struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBrokerHTTPBodyBytes)).Decode(&payload); err != nil {
		return nil, err
	}
	if strings.TrimSpace(payload.Error) != "" {
		return nil, errors.New(strings.TrimSpace(payload.Error))
	}
	raw := strings.TrimSpace(payload.Response)
	if raw == "" {
		return nil, errors.New("empty reranker response")
	}
	if strings.HasPrefix(raw, "```") {
		raw = stripCodeFences(raw)
	}
	var parsed struct {
		Scores []struct {
			ID    int     `json:"id"`
			Score float64 `json:"score"`
		} `json:"scores"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		start := strings.Index(raw, "{")
		end := strings.LastIndex(raw, "}")
		if start < 0 || end <= start {
			return nil, err
		}
		if err2 := json.Unmarshal([]byte(raw[start:end+1]), &parsed); err2 != nil {
			return nil, err2
		}
	}
	out := make([]float64, len(docs))
	for _, row := range parsed.Scores {
		if row.ID < 0 || row.ID >= len(out) {
			continue
		}
		out[row.ID] = clampFloat(row.Score, 0, 1)
	}
	return out, nil
}
