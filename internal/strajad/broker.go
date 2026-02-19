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
	"time"
)

const (
	brokerModeOllamaV1 = "broker_ollama_v1"

	maxBrokerHTTPBodyBytes = 4 * 1024 * 1024
)

var errUnsupportedBrokerProvider = errors.New("unsupported broker provider")

type plannerBroker interface {
	EnsureModel(ctx context.Context) error
	Plan(ctx context.Context, in plannerInput, fallback deterministicPlan) (brokerPlanDraft, error)
	Mode() string
}

type retrievalQueryBroker interface {
	ExpandRetrievalQuery(ctx context.Context, query, collection string) (queryExpansion, error)
}

type retrievalCoverageDraft struct {
	MissingAspects  []string `json:"missing_aspects,omitempty"`
	FollowupQueries []string `json:"followup_queries,omitempty"`
}

type retrievalCoverageBroker interface {
	CoverageFollowup(ctx context.Context, task, collection string, hits []searchHit) (retrievalCoverageDraft, error)
}

type brokerModelInspector interface {
	IsModelAvailable(ctx context.Context) (bool, error)
}

type brokerPlanDraft struct {
	Plan                 []string          `json:"plan"`
	RecommendedToolCalls []recommendedCall `json:"recommended_tool_calls"`
	ApprovalsNeeded      []string          `json:"approvals_needed"`
	SafetyNotes          []string          `json:"safety_notes"`
}

type brokerAnswerInput struct {
	Task          string            `json:"task"`
	Collection    string            `json:"collection,omitempty"`
	Plan          deterministicPlan `json:"plan"`
	SearchResults []searchHit       `json:"search_results,omitempty"`
	Snippets      []snippetHit      `json:"snippets,omitempty"`
	Documents     []brokerDocument  `json:"documents,omitempty"`
}

type brokerDocument struct {
	ID         string `json:"id"`
	Collection string `json:"collection,omitempty"`
	Title      string `json:"title,omitempty"`
	Content    string `json:"content"`
	Bytes      int    `json:"bytes,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

type brokerAnswerOutput struct {
	Response string         `json:"response"`
	Trace    map[string]any `json:"trace"`
}

type traceableAnswerBroker interface {
	AnswerWithTrace(ctx context.Context, in brokerAnswerInput) (brokerAnswerOutput, error)
}

func newPlannerBroker(cfg Config) (plannerBroker, error) {
	provider := strings.TrimSpace(strings.ToLower(cfg.BrokerProvider))
	switch provider {
	case "", "ollama":
		return newOllamaBroker(cfg.BrokerEndpoint, cfg.BrokerModel, cfg.BrokerTimeout, nil)
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedBrokerProvider, provider)
	}
}

// InstallBrokerModel pulls the configured broker model and returns when complete.
func InstallBrokerModel(ctx context.Context, cfg Config) error {
	cfg.applyDefaults()
	broker, err := newPlannerBroker(cfg)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return broker.EnsureModel(ctx)
}

// BrokerModelAvailable checks whether the configured broker model is already present locally.
func BrokerModelAvailable(ctx context.Context, cfg Config) (bool, error) {
	cfg.applyDefaults()
	provider := strings.TrimSpace(strings.ToLower(cfg.BrokerProvider))
	switch provider {
	case "", "ollama":
		broker, err := newOllamaBroker(cfg.BrokerEndpoint, cfg.BrokerModel, cfg.BrokerTimeout, nil)
		if err != nil {
			return false, err
		}
		return broker.IsModelAvailable(ctx)
	default:
		return false, fmt.Errorf("%w: %s", errUnsupportedBrokerProvider, provider)
	}
}

type ollamaBroker struct {
	endpoint string
	model    string
	timeout  time.Duration
	client   *http.Client
}

func newOllamaBroker(endpoint, model string, timeout time.Duration, client *http.Client) (*ollamaBroker, error) {
	endpoint = strings.TrimSpace(endpoint)
	endpoint = strings.TrimRight(endpoint, "/")
	if endpoint == "" {
		return nil, errors.New("broker endpoint is required")
	}
	model = strings.TrimSpace(model)
	if model == "" {
		return nil, errors.New("broker model is required")
	}
	if timeout <= 0 {
		return nil, errors.New("broker timeout must be > 0")
	}
	if client == nil {
		client = &http.Client{}
	}
	return &ollamaBroker{
		endpoint: endpoint,
		model:    model,
		timeout:  timeout,
		client:   client,
	}, nil
}

func (b *ollamaBroker) Mode() string {
	return brokerModeOllamaV1
}

func (b *ollamaBroker) EnsureModel(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	payload := map[string]any{
		"model":  b.model,
		"stream": false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint+"/api/pull", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("broker model pull failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("broker model pull failed: status=%d body=%q", resp.StatusCode, readBodyTruncated(resp.Body, 1024))
	}
	return nil
}

func (b *ollamaBroker) IsModelAvailable(ctx context.Context) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	reqCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, b.endpoint+"/api/tags", nil)
	if err != nil {
		return false, err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("broker model check failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("broker model check failed: status=%d body=%q", resp.StatusCode, readBodyTruncated(resp.Body, 1024))
	}

	var payload struct {
		Models []struct {
			Name  string `json:"name"`
			Model string `json:"model"`
		} `json:"models"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxBrokerHTTPBodyBytes))
	if err := dec.Decode(&payload); err != nil {
		return false, fmt.Errorf("decode broker tags response: %w", err)
	}
	target := strings.TrimSpace(b.model)
	if target == "" {
		return false, errors.New("broker model is required")
	}
	for _, model := range payload.Models {
		if brokerModelNameMatches(strings.TrimSpace(model.Name), target) {
			return true, nil
		}
		if brokerModelNameMatches(strings.TrimSpace(model.Model), target) {
			return true, nil
		}
	}
	return false, nil
}

func (b *ollamaBroker) Plan(ctx context.Context, in plannerInput, fallback deterministicPlan) (brokerPlanDraft, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	reqCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	promptPayload := map[string]any{
		"task":            strings.TrimSpace(in.Task),
		"collection":      normalizeCollectionName(in.Collection),
		"vault_locked":    in.VaultLocked,
		"presence_access": in.PresenceAccess,
		"budgets": map[string]any{
			"max_task_chars":      in.MaxTaskChars,
			"max_search_results":  in.MaxSearchResults,
			"max_snippet_objects": in.MaxSnippetObjects,
			"max_snippet_bytes":   in.MaxSnippetBytes,
			"max_snippet_chars":   in.MaxSnippetChars,
			"max_write_chars":     in.MaxWriteChars,
			"max_ingest_bytes":    in.MaxIngestBytes,
		},
		"fallback_plan": map[string]any{
			"plan":                   fallback.Plan,
			"recommended_tool_calls": fallback.RecommendedToolCalls,
			"approvals_needed":       fallback.ApprovalsNeeded,
			"safety_notes":           fallback.SafetyNotes,
		},
	}
	promptJSON, err := json.Marshal(promptPayload)
	if err != nil {
		return brokerPlanDraft{}, err
	}

	systemPrompt := strings.Join([]string{
		"You are Straja Vault's internal broker planner.",
		"Return only JSON with keys: plan, recommended_tool_calls, approvals_needed, safety_notes.",
		"Do not execute anything. Do not ask for unrestricted filesystem, shell, browser, or mailbox access.",
		"Never suggest bulk export or bypass of budgets/policies.",
		"Use only these tool names when recommending calls: vault.search, vault.read_snippets, vault.ingest, vault.write.",
		"Keep recommendations snippet-first and bounded.",
	}, "\n")

	reqBody := map[string]any{
		"model":  b.model,
		"stream": false,
		"format": "json",
		"options": map[string]any{
			"temperature": 0,
		},
		"prompt": systemPrompt + "\n\nInput JSON:\n" + string(promptJSON),
	}
	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return brokerPlanDraft{}, err
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, b.endpoint+"/api/generate", bytes.NewReader(encoded))
	if err != nil {
		return brokerPlanDraft{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return brokerPlanDraft{}, fmt.Errorf("broker request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return brokerPlanDraft{}, fmt.Errorf("broker request failed: status=%d body=%q", resp.StatusCode, readBodyTruncated(resp.Body, 1024))
	}

	var payload struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxBrokerHTTPBodyBytes))
	if err := dec.Decode(&payload); err != nil {
		return brokerPlanDraft{}, fmt.Errorf("decode broker response: %w", err)
	}
	if strings.TrimSpace(payload.Error) != "" {
		return brokerPlanDraft{}, errors.New(strings.TrimSpace(payload.Error))
	}
	return decodeBrokerPlanDraft(payload.Response)
}

func (b *ollamaBroker) ExpandRetrievalQuery(ctx context.Context, query, collection string) (queryExpansion, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	reqCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	input := map[string]any{
		"query":      sanitizeOneLine(query, "", 4000),
		"collection": normalizeCollectionName(collection),
	}
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return queryExpansion{}, err
	}

	systemPrompt := strings.Join([]string{
		"You are Straja Vault retrieval query expander.",
		"Return strict JSON only.",
		"Use keys: expanded_queries, must_terms, should_terms, negative_terms, inferred_filters, sensitivity_flags, risk_notes.",
		"expanded_queries should include 3 to 8 concise variants when possible.",
		"Use must_terms only for exact/high-value anchors (ids, quoted terms, dates, filenames).",
		"inferred_filters may include collection/date/source when strongly implied.",
		"negative_terms should suppress obvious wrong clusters when useful.",
		"sensitivity_flags may include bulk_export_intent=true when applicable.",
		"Never suggest policy bypass or unrestricted export.",
	}, "\n")

	reqBody := map[string]any{
		"model":  b.model,
		"stream": false,
		"format": "json",
		"options": map[string]any{
			"temperature": 0,
		},
		"prompt": systemPrompt + "\n\nInput JSON:\n" + string(inputJSON),
	}
	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return queryExpansion{}, err
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, b.endpoint+"/api/generate", bytes.NewReader(encoded))
	if err != nil {
		return queryExpansion{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return queryExpansion{}, fmt.Errorf("broker query expansion failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return queryExpansion{}, fmt.Errorf("broker query expansion failed: status=%d body=%q", resp.StatusCode, readBodyTruncated(resp.Body, 1024))
	}

	var payload struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxBrokerHTTPBodyBytes))
	if err := dec.Decode(&payload); err != nil {
		return queryExpansion{}, fmt.Errorf("decode broker query expansion response: %w", err)
	}
	if strings.TrimSpace(payload.Error) != "" {
		return queryExpansion{}, errors.New(strings.TrimSpace(payload.Error))
	}
	raw := strings.TrimSpace(payload.Response)
	if raw == "" {
		return queryExpansion{}, errors.New("empty broker query expansion response")
	}
	if strings.HasPrefix(raw, "```") {
		raw = stripCodeFences(raw)
	}
	var out queryExpansion
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		start := strings.Index(raw, "{")
		end := strings.LastIndex(raw, "}")
		if start >= 0 && end > start {
			if err2 := json.Unmarshal([]byte(raw[start:end+1]), &out); err2 == nil {
				return out, nil
			}
		}
		return queryExpansion{}, err
	}
	return out, nil
}

func (b *ollamaBroker) CoverageFollowup(ctx context.Context, task, collection string, hits []searchHit) (retrievalCoverageDraft, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	reqCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	trimmed := make([]searchHit, 0, minInt(len(hits), 6))
	for i, h := range hits {
		if i >= 6 {
			break
		}
		h.EvidenceChunkIDs = nil
		if len(h.TopSectionIDs) > 2 {
			h.TopSectionIDs = h.TopSectionIDs[:2]
		}
		trimmed = append(trimmed, h)
	}
	input := map[string]any{
		"task":       sanitizeOneLine(task, "", 4000),
		"collection": normalizeCollectionName(collection),
		"hits":       trimmed,
	}
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return retrievalCoverageDraft{}, err
	}

	systemPrompt := strings.Join([]string{
		"You are Straja Vault retrieval coverage analyzer.",
		"Return strict JSON only.",
		"Use keys: missing_aspects, followup_queries.",
		"followup_queries should be 2-5 concise retrieval queries grounded in the original task and current hits.",
		"missing_aspects should list what is still not covered by current hits.",
		"Do not add policy or safety prose.",
	}, "\n")

	reqBody := map[string]any{
		"model":  b.model,
		"stream": false,
		"format": "json",
		"options": map[string]any{
			"temperature": 0,
		},
		"prompt": systemPrompt + "\n\nInput JSON:\n" + string(inputJSON),
	}
	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return retrievalCoverageDraft{}, err
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, b.endpoint+"/api/generate", bytes.NewReader(encoded))
	if err != nil {
		return retrievalCoverageDraft{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return retrievalCoverageDraft{}, fmt.Errorf("broker coverage followup failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return retrievalCoverageDraft{}, fmt.Errorf("broker coverage followup failed: status=%d body=%q", resp.StatusCode, readBodyTruncated(resp.Body, 1024))
	}

	var payload struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxBrokerHTTPBodyBytes))
	if err := dec.Decode(&payload); err != nil {
		return retrievalCoverageDraft{}, fmt.Errorf("decode broker coverage followup response: %w", err)
	}
	if strings.TrimSpace(payload.Error) != "" {
		return retrievalCoverageDraft{}, errors.New(strings.TrimSpace(payload.Error))
	}
	raw := strings.TrimSpace(payload.Response)
	if raw == "" {
		return retrievalCoverageDraft{}, errors.New("empty broker coverage followup response")
	}
	if strings.HasPrefix(raw, "```") {
		raw = stripCodeFences(raw)
	}
	var out retrievalCoverageDraft
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		start := strings.Index(raw, "{")
		end := strings.LastIndex(raw, "}")
		if start >= 0 && end > start {
			if err2 := json.Unmarshal([]byte(raw[start:end+1]), &out); err2 == nil {
				return out, nil
			}
		}
		return retrievalCoverageDraft{}, err
	}
	out.FollowupQueries = compactQueries(out.FollowupQueries, 5)
	out.MissingAspects = compactTokens(dedupeStrings(out.MissingAspects), 8)
	return out, nil
}

func (b *ollamaBroker) AnswerWithTrace(ctx context.Context, in brokerAnswerInput) (brokerAnswerOutput, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	reqCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	inputPayload := map[string]any{
		"task":           sanitizeOneLine(in.Task, "", 8000),
		"collection":     normalizeCollectionName(in.Collection),
		"plan":           in.Plan,
		"search_results": in.SearchResults,
		"snippets":       in.Snippets,
		"documents":      in.Documents,
	}
	inputJSON, err := json.Marshal(inputPayload)
	if err != nil {
		return brokerAnswerOutput{}, err
	}

	systemPrompt := strings.Join([]string{
		"You are Straja Vault's local answer synthesizer.",
		"Use only provided search results, snippets, and documents.",
		"Do not claim access to data not included in input.",
		"Keep the answer concise, direct, and grounded.",
		"Write the answer for the end-user question directly.",
		"Never mention JSON, search result IDs, snippets, document IDs, or internal tracing.",
		"Never answer with 'refer to the manual/document' when usable snippet content exists.",
		"For 'how to' questions, return concrete steps/actions from the snippets.",
		"If snippets include action cues (press/hold/switch/set/ready indicator), output numbered steps directly.",
		"Do not tell the user to consult or refer to a manual when snippets already contain procedure details.",
		"If full documents are provided, treat them as primary context and answer directly from document content.",
		"Do not reinterpret domain terms when snippets clearly indicate product context (e.g., Subaru EyeSight).",
		"If there is at least one relevant snippet or document, answer from it and do not add a 'missing context' section.",
		"Only state missing context when all snippets and documents are irrelevant or unreadable.",
	}, "\n")
	fullPrompt := systemPrompt + "\n\nInput JSON:\n" + string(inputJSON)

	reqBody := map[string]any{
		"model":  b.model,
		"stream": false,
		"options": map[string]any{
			"temperature": 0,
		},
		"prompt": fullPrompt,
	}
	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return brokerAnswerOutput{}, err
	}

	trace := map[string]any{
		"provider":   "ollama",
		"endpoint":   b.endpoint + "/api/generate",
		"model":      b.model,
		"timeout_ms": b.timeout.Milliseconds(),
		"request": map[string]any{
			"model":   b.model,
			"stream":  false,
			"options": map[string]any{"temperature": 0},
			"prompt":  truncateUTF8ByBytes(fullPrompt, 12000),
		},
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, b.endpoint+"/api/generate", bytes.NewReader(encoded))
	if err != nil {
		trace["error"] = err.Error()
		return brokerAnswerOutput{Trace: trace}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		trace["error"] = err.Error()
		return brokerAnswerOutput{Trace: trace}, fmt.Errorf("broker request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body := readBodyTruncated(resp.Body, 1024)
		trace["error"] = fmt.Sprintf("status=%d body=%q", resp.StatusCode, body)
		return brokerAnswerOutput{Trace: trace}, fmt.Errorf("broker request failed: status=%d body=%q", resp.StatusCode, body)
	}

	var payload struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxBrokerHTTPBodyBytes))
	if err := dec.Decode(&payload); err != nil {
		trace["error"] = err.Error()
		return brokerAnswerOutput{Trace: trace}, fmt.Errorf("decode broker response: %w", err)
	}
	responseText := strings.TrimSpace(payload.Response)
	responseText = sanitizeBrokerAnswerResponse(responseText)
	trace["response"] = map[string]any{
		"response": truncateUTF8ByBytes(responseText, 12000),
		"error":    sanitizeOneLine(payload.Error, "", 512),
	}
	if strings.TrimSpace(payload.Error) != "" {
		trace["error"] = strings.TrimSpace(payload.Error)
		return brokerAnswerOutput{Trace: trace}, errors.New(strings.TrimSpace(payload.Error))
	}
	if responseText == "" {
		trace["error"] = "empty_response"
		return brokerAnswerOutput{Trace: trace}, errors.New("empty broker response")
	}
	return brokerAnswerOutput{
		Response: responseText,
		Trace:    trace,
	}, nil
}

func sanitizeBrokerAnswerResponse(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	cutMarkers := []string{
		"\ninput json:",
		"\ninput:",
		"\njson:",
		"\n```json",
		"\n{\"collection\"",
		"\n{\"task\"",
	}
	cutAt := -1
	for _, marker := range cutMarkers {
		if idx := strings.Index(lower, marker); idx >= 0 {
			if cutAt < 0 || idx < cutAt {
				cutAt = idx
			}
		}
	}
	if cutAt >= 0 {
		s = strings.TrimSpace(s[:cutAt])
	}
	if strings.HasPrefix(strings.ToLower(s), "input json:") {
		return ""
	}
	return strings.TrimSpace(s)
}

func decodeBrokerPlanDraft(raw string) (brokerPlanDraft, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return brokerPlanDraft{}, errors.New("empty broker response")
	}
	candidate := raw
	if strings.HasPrefix(candidate, "```") {
		candidate = stripCodeFences(candidate)
	}

	var draft brokerPlanDraft
	if err := json.Unmarshal([]byte(candidate), &draft); err == nil {
		return draft, nil
	}

	start := strings.Index(candidate, "{")
	end := strings.LastIndex(candidate, "}")
	if start >= 0 && end > start {
		if err := json.Unmarshal([]byte(candidate[start:end+1]), &draft); err == nil {
			return draft, nil
		}
	}
	return brokerPlanDraft{}, errors.New("invalid broker response json")
}

func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
	}
	if strings.HasSuffix(s, "```") {
		s = strings.TrimSuffix(s, "```")
	}
	return strings.TrimSpace(s)
}

func readBodyTruncated(r io.Reader, max int64) string {
	if r == nil || max <= 0 {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(r, max))
	return strings.TrimSpace(string(b))
}

func brokerModelNameMatches(installed, target string) bool {
	installed = strings.TrimSpace(installed)
	target = strings.TrimSpace(target)
	if installed == "" || target == "" {
		return false
	}
	if installed == target {
		return true
	}
	if !strings.Contains(target, ":") && installed == target+":latest" {
		return true
	}
	if !strings.Contains(installed, ":") && target == installed+":latest" {
		return true
	}
	return false
}
