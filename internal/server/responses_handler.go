package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/activation"
	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/redact"
	"github.com/straja-ai/straja/internal/safety"
	"go.opentelemetry.io/otel/trace"
)

func (s *Server) handleResponses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestID := newRequestID()
	w.Header().Set("X-Straja-Request-Id", requestID)

	start := time.Now()
	ctx := r.Context()
	ctx, root := s.startSpan(ctx, "straja.request", trace.SpanKindServer, map[string]interface{}{
		"straja.version":                    version,
		"http.method":                       r.Method,
		"http.route":                        "/v1/responses",
		"straja.strajaguard.enabled":        s.strajaGuardEnabled(),
		"straja.strajaguard.loaded":         s.strajaGuardEnabled(),
		"straja.strajaguard.bundle_version": s.activeBundleVer,
	})
	defer root.End()

	// Auth: extract API key and map to project
	authCtx, authSpan := s.startSpan(ctx, "straja.auth", trace.SpanKindInternal, nil)
	apiKey, ok := parseBearerToken(r.Header.Get("Authorization"))
	setSpanAttrs(authSpan, map[string]interface{}{
		"straja.auth.api_key_present": apiKey != "",
	})
	if !ok || apiKey == "" {
		setSpanAttrs(authSpan, map[string]interface{}{"straja.auth.result": "missing"})
		authSpan.End()
		writeOpenAIError(w, http.StatusUnauthorized, "Invalid or missing API key", "authentication_error")
		return
	}

	project, ok := s.auth.Lookup(apiKey)
	setSpanAttrs(authSpan, map[string]interface{}{
		"straja.auth.project_resolved": ok,
	})
	if !ok {
		setSpanAttrs(authSpan, map[string]interface{}{"straja.auth.result": "invalid"})
		authSpan.End()
		writeOpenAIError(w, http.StatusUnauthorized, "Invalid API key", "authentication_error")
		return
	}
	setSpanAttrs(authSpan, map[string]interface{}{"straja.auth.result": "ok"})
	authSpan.End()

	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		if isRequestTooLarge(err) {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "Request body too large", "invalid_request_error")
			return
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	model := ""
	if v, ok := payload["model"].(string); ok {
		model = strings.TrimSpace(v)
	}
	stream := false
	if v, ok := payload["stream"].(bool); ok {
		stream = v
	}
	mode := activation.ModeNonStream
	if stream {
		mode = activation.ModeStream
	}

	var cancel context.CancelFunc
	if s.cfg.Server.UpstreamTimeout > 0 {
		ctx, cancel = context.WithTimeout(authCtx, s.cfg.Server.UpstreamTimeout)
	} else {
		ctx, cancel = context.WithCancel(authCtx)
	}
	defer cancel()

	// Determine provider for this project
	providerName := project.Provider
	if providerName == "" {
		providerName = s.defaultProvider
	}

	provCfg, ok := s.cfg.Providers[providerName]
	if !ok {
		redact.Logf("no provider %q for project %q", providerName, project.ID)
		writeOpenAIError(w, http.StatusInternalServerError, "Straja misconfiguration: unknown provider for project", "configuration_error")
		return
	}

	infReq := &inference.Request{
		RequestID: requestID,
		ProjectID: project.ID,
		Model:     model,
		Messages:  []inference.Message{},
		Timings:   &inference.Timings{},
	}
	s.requestStore.Start(requestID, project.ID)
	decision := "allow"
	statusCode := http.StatusOK
	defer logTimingDebug(project.ID, providerName, decision, infReq.Timings)
	defer func() {
		setSpanAttrs(root, map[string]interface{}{
			"straja.project_id":                 project.ID,
			"straja.provider_id":                providerName,
			"straja.provider_type":              s.providerTypes[providerName],
			"straja.model":                      infReq.Model,
			"straja.decision":                   decision,
			"straja.policy_hits_total":          len(infReq.PolicyHits),
			"straja.policy_categories":          infReq.PolicyHits,
			"straja.blocked":                    strings.HasPrefix(decision, "blocked"),
			"straja.strajaguard.bundle_version": s.activeBundleVer,
			"http.status_code":                  statusCode,
		})
		if s.telemetry != nil {
			s.telemetry.RecordRequestMetrics(decision, s.providerTypes[providerName], project.ID, float64(time.Since(start).Milliseconds()), durationMs(infReq.Timings.Provider), durationMs(infReq.Timings.StrajaGuard), len(infReq.PolicyHits))
		}
	}()

	if model != "" && !s.isModelAllowed(model, project.ID, providerName) {
		decision = "blocked_request"
		statusCode = http.StatusBadRequest
		writeOpenAIError(w, http.StatusBadRequest, "Model not allowed", "invalid_request_error")
		return
	}

	inputVal, hasInput := payload["input"]
	if !hasInput {
		if msgVal, ok := payload["messages"]; ok {
			if converted, ok := messagesToResponsesInput(msgVal); ok {
				inputVal = converted
				hasInput = true
				payload["input"] = converted
				delete(payload, "messages")
			}
		}
	}
	if hasInput {
		var err error
		inputVal, infReq, _, _, err = s.hardenResponsesInput(ctx, project.ID, model, inputVal)
		infReq.RequestID = requestID
		if err != nil {
			decision = "blocked_before"
			statusCode = http.StatusForbidden
			s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionBlockedBefore, mode)
			writePolicyBlockedError(w, http.StatusForbidden, err.Error())
			return
		}
		payload["input"] = inputVal
	}

	body, err := json.Marshal(payload)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error")
		return
	}

	providerStart := time.Now()
	upstreamResp, err := s.doResponsesUpstream(ctx, provCfg, providerName, r.Header, body)
	if infReq.Timings != nil {
		infReq.Timings.Provider = time.Since(providerStart)
	}
	if err != nil {
		redact.Logf("provider %q error: %v", providerName, err)
		decision = "error_provider"
		statusCode = http.StatusBadGateway
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider, mode)
		writeOpenAIError(w, http.StatusBadGateway, "Upstream provider error", "provider_error")
		return
	}
	defer upstreamResp.Body.Close()

	if upstreamResp.StatusCode >= 400 {
		decision = "error_provider"
		statusCode = upstreamResp.StatusCode
		copyHeaders(w.Header(), upstreamResp.Header, nil)
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider, mode)
		w.WriteHeader(upstreamResp.StatusCode)
		_, _ = io.Copy(w, upstreamResp.Body)
		return
	}

	if stream {
		setSSEHeaders(w.Header())
		w.WriteHeader(upstreamResp.StatusCode)
		capture := newSSECapture(s.cfg.Server.MaxNonStreamResponseBytes)
		if err := copyUpstreamBodyWithCapture(w, upstreamResp.Body, capture); err != nil && !errors.Is(err, context.Canceled) {
			cancel()
			redact.Logf("responses: streaming copy failed: %v", err)
		}
		postDecision := runPostCheckForStream(ctx, s, infReq, capture)
		if postDecision == "blocked" {
			decision = "blocked_after"
		} else {
			decision = "allow"
		}
		statusCode = upstreamResp.StatusCode
		if postDecision == "blocked" {
			s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionBlockedAfter, mode)
		} else {
			s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionAllow, mode)
		}
		return
	}

	respBody, err := readLimited(upstreamResp.Body, s.cfg.Server.MaxNonStreamResponseBytes)
	if err != nil {
		decision = "error_provider"
		statusCode = http.StatusBadGateway
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider, mode)
		writeOpenAIError(w, http.StatusBadGateway, "Upstream provider error", "provider_error")
		return
	}

	updatedBody := respBody
	postDecision := "allow"
	if len(respBody) > 0 {
		var parsed map[string]any
		if err := json.Unmarshal(respBody, &parsed); err == nil {
			agg := newPostCheckAggregator(ctx, s, project.ID, model, infReq.RequestID)
			if _, err := applyPostCheckToResponse(parsed, agg); err != nil {
				postDecision = "blocked"
			}
			post := agg.Result()
			infReq.PostPolicyHits = post.postReq.PolicyHits
			infReq.PostPolicyDecisions = post.postReq.PolicyDecisions
			infReq.PostDecision = post.decision
			infReq.OutputPreview = outputPreview(post.outputs)
			infReq.PostCheckLatency = post.latency
			infReq.PostSafetyScores = post.postReq.SecurityScores
			infReq.PostSafetyFlags = post.postReq.SecurityFlags
			postDecision = post.decision

			if postDecision == "blocked" {
				decision = "blocked_after"
				statusCode = http.StatusForbidden
				s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionBlockedAfter, mode)
				writePolicyBlockedError(w, http.StatusForbidden, "Output blocked by Straja policy (after model)")
				return
			}

			if postDecision == "redacted" {
				if body, err := json.Marshal(parsed); err == nil {
					updatedBody = body
				}
			}
		}
	}

	decision = "allow"
	statusCode = upstreamResp.StatusCode
	copyHeaders(w.Header(), upstreamResp.Header, nil)
	w.Header().Set("Content-Type", "application/json")
	s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionAllow, mode)
	w.WriteHeader(upstreamResp.StatusCode)
	_, _ = w.Write(updatedBody)
}

func (s *Server) doResponsesUpstream(ctx context.Context, pcfg config.ProviderConfig, providerName string, incoming http.Header, body []byte) (*http.Response, error) {
	baseURL := resolveProviderBaseURL(pcfg)
	if baseURL == "" {
		return nil, fmt.Errorf("provider %q base_url is empty", providerName)
	}
	apiKey := resolveProviderAPIKey(pcfg)
	if strings.EqualFold(pcfg.Type, "openai") && strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("provider %q api key missing", providerName)
	}

	targetURL := strings.TrimRight(baseURL, "/") + "/responses"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	copyHeaders(req.Header, incoming, map[string]struct{}{
		"Authorization":     {},
		"Content-Length":    {},
		"Content-Type":      {},
		"Host":              {},
		"Accept-Encoding":   {},
		"Connection":        {},
		"Proxy-Connection":  {},
		"Transfer-Encoding": {},
		"Upgrade":           {},
	})

	client := responsesHTTPClient()
	return client.Do(req)
}

func (s *Server) hardenResponsesInput(ctx context.Context, projectID, model string, input any) (any, *inference.Request, int, int, error) {
	agg := &inference.Request{
		ProjectID: projectID,
		Model:     model,
		Messages:  []inference.Message{},
		Timings:   &inference.Timings{},
	}
	segments := 0
	totalChars := 0

	apply := func(role, text string) (string, error) {
		segments++
		totalChars += len(text)

		req := &inference.Request{
			ProjectID: projectID,
			Model:     model,
			Messages: []inference.Message{
				{
					Role:    normalizeRole(role),
					Content: text,
				},
			},
			Timings: &inference.Timings{},
		}

		preStart := time.Now()
		err := s.policy.BeforeModel(ctx, req)
		if req.Timings != nil {
			req.Timings.PrePolicy = time.Since(preStart)
		}
		mergeInferenceRequest(agg, req)

		if len(req.Messages) > 0 {
			if len(agg.Messages) == 0 {
				agg.Messages = append(agg.Messages, req.Messages[0])
			} else {
				agg.Messages[0] = req.Messages[0]
			}
		}
		return req.Messages[0].Content, err
	}

	sanitized, err := walkResponsesInput(input, "", apply)
	return sanitized, agg, segments, totalChars, err
}

func walkResponsesInput(val any, role string, apply func(role, text string) (string, error)) (any, error) {
	switch v := val.(type) {
	case string:
		return apply(role, v)
	case []any:
		for i := range v {
			next, err := walkResponsesInput(v[i], role, apply)
			if err != nil {
				return val, err
			}
			v[i] = next
		}
		return v, nil
	case map[string]any:
		nextRole := role
		if r, ok := v["role"].(string); ok {
			nextRole = r
		}
		if textVal, ok := v["text"]; ok {
			text, ok := textVal.(string)
			if !ok {
				redact.Logf("responses: input.text is non-string; leaving untouched")
			} else {
				updated, err := apply(nextRole, text)
				if err != nil {
					return val, err
				}
				v["text"] = updated
			}
		}
		if contentVal, ok := v["content"]; ok {
			updated, err := walkResponsesInput(contentVal, nextRole, apply)
			if err != nil {
				return val, err
			}
			v["content"] = updated
		}
		return v, nil
	default:
		return val, nil
	}
}

func normalizeRole(role string) string {
	role = strings.TrimSpace(strings.ToLower(role))
	if role == "" {
		return "user"
	}
	return role
}

func messagesToResponsesInput(val any) (any, bool) {
	msgs, ok := val.([]any)
	if !ok || len(msgs) == 0 {
		return nil, false
	}
	out := make([]any, 0, len(msgs))
	for _, raw := range msgs {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		role := ""
		if r, ok := m["role"].(string); ok {
			role = r
		}
		role = normalizeRole(role)
		contentVal, ok := m["content"]
		if !ok {
			continue
		}
		switch c := contentVal.(type) {
		case string:
			out = append(out, map[string]any{
				"role": role,
				"content": []map[string]any{
					{
						"type": "input_text",
						"text": c,
					},
				},
			})
		case []any:
			out = append(out, map[string]any{
				"role":    role,
				"content": c,
			})
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func mergeInferenceRequest(dst, src *inference.Request) {
	if dst == nil || src == nil {
		return
	}
	if dst.ProjectID == "" {
		dst.ProjectID = src.ProjectID
	}
	if dst.Model == "" {
		dst.Model = src.Model
	}
	if dst.Timings != nil && src.Timings != nil {
		dst.Timings.PrePolicy += src.Timings.PrePolicy
		dst.Timings.StrajaGuard += src.Timings.StrajaGuard
	}

	for _, hit := range src.PolicyHits {
		if !containsString(dst.PolicyHits, hit) {
			dst.PolicyHits = append(dst.PolicyHits, hit)
		}
	}
	dst.DetectionSignals = append(dst.DetectionSignals, src.DetectionSignals...)

	for _, decision := range src.PolicyDecisions {
		if !hasPolicyDecision(dst.PolicyDecisions, decision.Category) {
			dst.PolicyDecisions = append(dst.PolicyDecisions, decision)
		}
	}

	if len(src.SecurityScores) > 0 {
		if dst.SecurityScores == nil {
			dst.SecurityScores = make(map[string]float32, len(src.SecurityScores))
		}
		for k, v := range src.SecurityScores {
			if cur, ok := dst.SecurityScores[k]; !ok || v > cur {
				dst.SecurityScores[k] = v
			}
		}
	}

	for _, flag := range src.SecurityFlags {
		if !containsString(dst.SecurityFlags, flag) {
			dst.SecurityFlags = append(dst.SecurityFlags, flag)
		}
	}

	if len(src.PIIEntities) > 0 {
		dst.PIIEntities = mergePIIEntities(dst.PIIEntities, src.PIIEntities)
	}
}

func hasPolicyDecision(decisions []safety.PolicyHit, category string) bool {
	for _, d := range decisions {
		if d.Category == category {
			return true
		}
	}
	return false
}

func mergePIIEntities(dst, src []safety.PIIEntity) []safety.PIIEntity {
	if len(src) == 0 {
		return dst
	}
	if len(dst) == 0 {
		out := make([]safety.PIIEntity, len(src))
		copy(out, src)
		return out
	}
	exists := make(map[string]struct{}, len(dst))
	for _, e := range dst {
		key := fmt.Sprintf("%s:%d:%d:%s", e.EntityType, e.StartByte, e.EndByte, e.Source)
		exists[key] = struct{}{}
	}
	for _, e := range src {
		key := fmt.Sprintf("%s:%d:%d:%s", e.EntityType, e.StartByte, e.EndByte, e.Source)
		if _, ok := exists[key]; ok {
			continue
		}
		dst = append(dst, e)
		exists[key] = struct{}{}
	}
	return dst
}

func setSSEHeaders(h http.Header) {
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Del("Content-Length")
}

func copyUpstreamBody(w http.ResponseWriter, body io.Reader, flush bool) error {
	if !flush {
		_, err := io.Copy(w, body)
		return err
	}
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func copyHeaders(dst, src http.Header, skip map[string]struct{}) {
	for k, vals := range src {
		if skip != nil {
			if _, ok := skip[k]; ok {
				continue
			}
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func resolveProviderAPIKey(pcfg config.ProviderConfig) string {
	apiKey := strings.TrimSpace(os.Getenv(pcfg.APIKeyEnv))
	if apiKey == "" {
		apiKey = strings.TrimSpace(pcfg.APIKey)
	}
	return apiKey
}

func resolveProviderBaseURL(pcfg config.ProviderConfig) string {
	if strings.TrimSpace(pcfg.BaseURL) != "" {
		return strings.TrimSpace(pcfg.BaseURL)
	}
	switch strings.ToLower(strings.TrimSpace(pcfg.Type)) {
	case "openai":
		return "https://api.openai.com/v1"
	case "mock":
		return "http://127.0.0.1:18080"
	default:
		return ""
	}
}

func responsesHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DisableCompression = true
	return &http.Client{
		Transport: tr,
	}
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		return io.ReadAll(r)
	}
	limited := io.LimitReader(r, max+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("response exceeded limit (%d bytes)", max)
	}
	return data, nil
}

type sseCapture struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func newSSECapture(limit int64) *sseCapture {
	return &sseCapture{limit: limit}
}

func (c *sseCapture) Write(p []byte) {
	if c == nil || c.truncated {
		return
	}
	if c.limit > 0 && int64(c.buf.Len()+len(p)) > c.limit {
		remaining := int64(c.limit - int64(c.buf.Len()))
		if remaining > 0 {
			c.buf.Write(p[:remaining])
		}
		c.truncated = true
		return
	}
	c.buf.Write(p)
}

func (c *sseCapture) Bytes() []byte {
	if c == nil {
		return nil
	}
	return c.buf.Bytes()
}

func copyUpstreamBodyWithCapture(w http.ResponseWriter, body io.Reader, capture *sseCapture) error {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if capture != nil {
				capture.Write(chunk)
			}
			if _, werr := w.Write(chunk); werr != nil {
				return werr
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func applyPostCheckToResponse(resp map[string]any, agg *postCheckAggregator) (int, error) {
	if resp == nil || agg == nil {
		return 0, nil
	}
	output, ok := resp["output"].([]any)
	if !ok || len(output) == 0 {
		return 0, nil
	}
	processed := 0
	for i := range output {
		item, ok := output[i].(map[string]any)
		if !ok {
			continue
		}
		content, ok := item["content"].([]any)
		if !ok {
			continue
		}
		for j := range content {
			seg, ok := content[j].(map[string]any)
			if !ok {
				continue
			}
			t, _ := seg["type"].(string)
			if t == "" {
				t = "output_text"
			}
			if !isOutputContentType(t) {
				continue
			}
			text, ok := seg["text"].(string)
			if !ok {
				continue
			}
			updated, err := agg.Check(text)
			seg["text"] = updated
			processed++
			if err != nil {
				return processed, err
			}
		}
	}
	if processed == 0 {
		if txt, ok := resp["output_text"].(string); ok {
			updated, err := agg.Check(txt)
			resp["output_text"] = updated
			processed++
			if err != nil {
				return processed, err
			}
		}
	}
	return processed, nil
}

func isOutputContentType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "output_text", "summary_text", "refusal", "text":
		return true
	default:
		return false
	}
}

func runPostCheckForStream(ctx context.Context, s *Server, infReq *inference.Request, capture *sseCapture) string {
	if infReq == nil || capture == nil || capture.truncated {
		if infReq != nil {
			infReq.PostDecision = "allow"
		}
		return "allow"
	}
	outputText := extractOutputTextFromSSE(capture.Bytes())
	if strings.TrimSpace(outputText) == "" {
		infReq.PostDecision = "allow"
		return "allow"
	}
	agg := newPostCheckAggregator(ctx, s, infReq.ProjectID, infReq.Model, infReq.RequestID)
	_, _ = agg.Check(outputText)
	post := agg.Result()
	infReq.PostPolicyHits = post.postReq.PolicyHits
	infReq.PostPolicyDecisions = post.postReq.PolicyDecisions
	infReq.PostDecision = post.decision
	infReq.OutputPreview = outputPreview(post.outputs)
	infReq.PostCheckLatency = post.latency
	infReq.PostSafetyScores = post.postReq.SecurityScores
	infReq.PostSafetyFlags = post.postReq.SecurityFlags
	return post.decision
}

func extractOutputTextFromSSE(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	payload := string(data)
	events := strings.Split(payload, "\n\n")
	var builder strings.Builder
	hasDelta := false
	fullText := ""
	for _, e := range events {
		evt, data := parseSSEEvent(e)
		if strings.TrimSpace(data) == "" {
			continue
		}
		if data == "[DONE]" {
			continue
		}
		text, fromDelta := extractTextFromSSEData(evt, data)
		if text == "" {
			continue
		}
		if fromDelta {
			builder.WriteString(text)
			hasDelta = true
			continue
		}
		if !hasDelta && fullText == "" {
			fullText = text
		}
	}
	if hasDelta {
		return builder.String()
	}
	return fullText
}

func parseSSEEvent(chunk string) (string, string) {
	event := ""
	dataLines := []string{}
	for _, line := range strings.Split(chunk, "\n") {
		if strings.HasPrefix(line, "event:") {
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	return event, strings.Join(dataLines, "\n")
}

func extractTextFromSSEData(event, data string) (string, bool) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(data), &obj); err != nil {
		return "", false
	}
	if t, ok := obj["type"].(string); ok {
		switch t {
		case "response.output_text.delta":
			if delta, ok := obj["delta"].(string); ok {
				return delta, true
			}
		case "response.output_text.done":
			if txt, ok := obj["text"].(string); ok {
				return txt, false
			}
		case "response.completed":
			if resp, ok := obj["response"].(map[string]any); ok {
				return extractOutputTextFromResponse(resp), false
			}
		}
	}
	if delta, ok := obj["delta"].(map[string]any); ok {
		if txt, ok := delta["text"].(string); ok {
			return txt, true
		}
	}
	if txt, ok := obj["output_text"].(string); ok {
		return txt, false
	}
	if txt, ok := obj["text"].(string); ok {
		return txt, false
	}
	return "", false
}

func extractOutputTextFromResponse(resp map[string]any) string {
	output, ok := resp["output"].([]any)
	if !ok {
		return ""
	}
	var builder strings.Builder
	for _, item := range output {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		content, ok := obj["content"].([]any)
		if !ok {
			continue
		}
		for _, seg := range content {
			segObj, ok := seg.(map[string]any)
			if !ok {
				continue
			}
			t, _ := segObj["type"].(string)
			if !isOutputContentType(t) {
				continue
			}
			if txt, ok := segObj["text"].(string); ok {
				builder.WriteString(txt)
			}
		}
	}
	return builder.String()
}

func writePolicyBlockedError(w http.ResponseWriter, status int, message string) {
	if strings.TrimSpace(message) == "" {
		message = "Request blocked by Straja policy"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(openAIErrorBody{
		Error: openAIErrorDetail{
			Message: "Request blocked by Straja policy: " + message,
			Type:    "straja_policy_violation",
			Code:    "policy_blocked",
		},
	})
}
