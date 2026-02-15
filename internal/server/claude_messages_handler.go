package server

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

	"github.com/straja-ai/straja/internal/activation"
	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/redact"
	"go.opentelemetry.io/otel/trace"
)

const defaultClaudeAPIVersion = "2023-06-01"

func (s *Server) handleClaudeMessages(w http.ResponseWriter, r *http.Request) {
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
		"http.route":                        "/v1/messages",
		"straja.strajaguard.enabled":        s.strajaGuardEnabled(),
		"straja.strajaguard.loaded":         s.strajaGuardEnabled(),
		"straja.strajaguard.bundle_version": s.activeBundleVer,
	})
	defer root.End()

	authCtx, authSpan := s.startSpan(ctx, "straja.auth", trace.SpanKindInternal, nil)
	project, authMode, ok := s.resolveAuthProject(r)
	setSpanAttrs(authSpan, map[string]interface{}{
		"straja.auth.mode": authMode,
	})
	if !ok {
		setSpanAttrs(authSpan, map[string]interface{}{"straja.auth.result": "missing"})
		authSpan.End()
		writeClaudeError(w, http.StatusUnauthorized, "Invalid or missing API key", "authentication_error")
		return
	}
	setSpanAttrs(authSpan, map[string]interface{}{"straja.auth.result": "ok"})
	authSpan.End()

	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		if isRequestTooLarge(err) {
			writeClaudeError(w, http.StatusRequestEntityTooLarge, "Request body too large", "invalid_request_error")
			return
		}
		writeClaudeError(w, http.StatusBadRequest, "Invalid JSON body", "invalid_request_error")
		return
	}

	model := ""
	if v, ok := payload["model"].(string); ok {
		model = strings.TrimSpace(v)
	}
	if model == "" {
		writeClaudeError(w, http.StatusBadRequest, "model is required", "invalid_request_error")
		return
	}
	stream := false
	if v, ok := payload["stream"].(bool); ok {
		stream = v
	}
	mode := activation.ModeNonStream
	if stream {
		mode = activation.ModeStream
	}

	if _, ok := payload["max_tokens"]; !ok {
		payload["max_tokens"] = 1024
	}

	var cancel context.CancelFunc
	if s.cfg.Server.UpstreamTimeout > 0 {
		ctx, cancel = context.WithTimeout(authCtx, s.cfg.Server.UpstreamTimeout)
	} else {
		ctx, cancel = context.WithCancel(authCtx)
	}
	defer cancel()

	providerName := project.Provider
	if providerName == "" {
		providerName = s.defaultProvider
	}

	provCfg, ok := s.cfg.Providers[providerName]
	if !ok {
		redact.Logf("no provider %q for project %q", providerName, project.ID)
		writeClaudeError(w, http.StatusInternalServerError, "Straja misconfiguration: unknown provider for project", "invalid_request_error")
		return
	}
	if !strings.EqualFold(strings.TrimSpace(provCfg.Type), "claude") {
		writeClaudeError(w, http.StatusBadRequest, "Project provider does not support Claude Messages API", "invalid_request_error")
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

	if !s.isModelAllowed(model, project.ID, providerName) {
		decision = "blocked_request"
		statusCode = http.StatusBadRequest
		writeClaudeError(w, http.StatusBadRequest, "Model not allowed", "invalid_request_error")
		return
	}

	var err error
	payload, infReq, err = s.hardenClaudeMessagesPayload(ctx, payload, infReq)
	if err != nil {
		decision = "blocked_before"
		statusCode = http.StatusForbidden
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionBlockedBefore, mode)
		writeClaudePolicyBlockedError(w, err.Error())
		return
	}

	body, err := json.Marshal(payload)
	if err != nil {
		writeClaudeError(w, http.StatusBadRequest, "Invalid JSON body", "invalid_request_error")
		return
	}

	providerStart := time.Now()
	upstreamResp, err := s.doClaudeMessagesUpstream(ctx, provCfg, providerName, r.Header, body)
	if infReq.Timings != nil {
		infReq.Timings.Provider = time.Since(providerStart)
	}
	if err != nil {
		redact.Logf("provider %q error: %v", providerName, err)
		decision = "error_provider"
		statusCode = http.StatusBadGateway
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider, mode)
		writeClaudeError(w, http.StatusBadGateway, "Upstream provider error", "api_error")
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
			redact.Logf("claude messages: streaming copy failed: %v", err)
		}
		postDecision, outputText := runPostCheckForClaudeStream(ctx, s, infReq, capture)
		_ = s.applyResponseGuard(infReq, s.evaluateResponseGuard(outputText), true)
		decision = "allow"
		statusCode = upstreamResp.StatusCode
		_ = postDecision
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionAllow, mode)
		return
	}

	respBody, err := readLimited(upstreamResp.Body, s.cfg.Server.MaxNonStreamResponseBytes)
	if err != nil {
		decision = "error_provider"
		statusCode = http.StatusBadGateway
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider, mode)
		writeClaudeError(w, http.StatusBadGateway, "Upstream provider error", "api_error")
		return
	}

	updatedBody := respBody
	postDecision := "allow"
	if len(respBody) > 0 {
		var parsed map[string]any
		if err := json.Unmarshal(respBody, &parsed); err == nil {
			agg := newPostCheckAggregator(ctx, s, project.ID, model, infReq.RequestID)
			if _, err := applyPostCheckToClaudeResponse(parsed, agg); err != nil {
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

			if postDecision == "redacted" {
				if body, err := json.Marshal(parsed); err == nil {
					updatedBody = body
				}
			}

			outputText := strings.Join(post.outputs, "\n")
			_ = s.applyResponseGuard(infReq, s.evaluateResponseGuard(outputText), false)
		}
	}

	decision = "allow"
	statusCode = upstreamResp.StatusCode
	skipHeaders := map[string]struct{}{}
	if postDecision == "redacted" {
		skipHeaders["Content-Length"] = struct{}{}
		skipHeaders["Content-Encoding"] = struct{}{}
	}
	copyHeaders(w.Header(), upstreamResp.Header, skipHeaders)
	w.Header().Set("Content-Type", "application/json")
	s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionAllow, mode)
	w.WriteHeader(upstreamResp.StatusCode)
	_, _ = w.Write(updatedBody)
}

func (s *Server) hardenClaudeMessagesPayload(ctx context.Context, payload map[string]any, req *inference.Request) (map[string]any, *inference.Request, error) {
	if req == nil {
		req = &inference.Request{
			Messages: []inference.Message{},
			Timings:  &inference.Timings{},
		}
	}

	segments := 0
	totalChars := 0
	apply := func(role, text string) (string, error) {
		segments++
		totalChars += len(text)
		if s.cfg.Server.MaxMessages > 0 && segments > s.cfg.Server.MaxMessages {
			return text, errors.New("Request too large")
		}
		if s.cfg.Server.MaxTotalMessageChars > 0 && totalChars > s.cfg.Server.MaxTotalMessageChars {
			return text, errors.New("Request too large")
		}

		subReq := &inference.Request{
			RequestID: req.RequestID,
			ProjectID: req.ProjectID,
			Model:     req.Model,
			Messages: []inference.Message{
				{
					Role:    normalizeRole(role),
					Content: text,
				},
			},
			Timings: &inference.Timings{},
		}

		preStart := time.Now()
		err := s.policy.BeforeModel(ctx, subReq)
		if subReq.Timings != nil {
			subReq.Timings.PrePolicy = time.Since(preStart)
		}

		saved := req.Messages
		mergeInferenceRequest(req, subReq)
		req.Messages = saved
		req.Messages = append(req.Messages, subReq.Messages...)
		return subReq.Messages[0].Content, err
	}

	if rawSystem, ok := payload["system"]; ok {
		nextSystem, err := walkClaudeContent(rawSystem, "system", apply)
		if err != nil {
			return payload, req, err
		}
		payload["system"] = nextSystem
	}

	rawMessages, ok := payload["messages"]
	if !ok {
		return payload, req, errors.New("messages is required")
	}
	nextMessages, err := walkClaudeMessages(rawMessages, apply)
	if err != nil {
		return payload, req, err
	}
	payload["messages"] = nextMessages
	return payload, req, nil
}

func walkClaudeMessages(value any, apply func(role, text string) (string, error)) (any, error) {
	msgs, ok := value.([]any)
	if !ok {
		return value, errors.New("messages must be an array")
	}
	for i := range msgs {
		msg, ok := msgs[i].(map[string]any)
		if !ok {
			continue
		}
		role := ""
		if rawRole, ok := msg["role"].(string); ok {
			role = normalizeRole(rawRole)
		}
		if role == "" {
			role = "user"
		}
		content, ok := msg["content"]
		if !ok {
			continue
		}
		nextContent, err := walkClaudeContent(content, role, apply)
		if err != nil {
			return value, err
		}
		msg["content"] = nextContent
	}
	return msgs, nil
}

func walkClaudeContent(value any, role string, apply func(role, text string) (string, error)) (any, error) {
	switch v := value.(type) {
	case string:
		return apply(role, v)
	case []any:
		for i := range v {
			next, err := walkClaudeContent(v[i], role, apply)
			if err != nil {
				return value, err
			}
			v[i] = next
		}
		return v, nil
	case map[string]any:
		if nestedRole, ok := v["role"].(string); ok {
			role = normalizeRole(nestedRole)
		}
		if textValue, ok := v["text"]; ok {
			if text, ok := textValue.(string); ok {
				updated, err := apply(role, text)
				if err != nil {
					return value, err
				}
				v["text"] = updated
			}
		}
		if contentValue, ok := v["content"]; ok {
			next, err := walkClaudeContent(contentValue, role, apply)
			if err != nil {
				return value, err
			}
			v["content"] = next
		}
		// Tool-use payloads can contain natural-language strings in nested JSON.
		// Scan all string leaves so policy checks apply consistently.
		if inputValue, ok := v["input"]; ok {
			next, _, err := applyToStructuredStringLeaves(inputValue, apply, role)
			if err != nil {
				return value, err
			}
			v["input"] = next
		}
		return v, nil
	default:
		return value, nil
	}
}

func (s *Server) doClaudeMessagesUpstream(ctx context.Context, pcfg config.ProviderConfig, providerName string, incoming http.Header, body []byte) (*http.Response, error) {
	if !strings.EqualFold(strings.TrimSpace(pcfg.Type), "claude") {
		return nil, fmt.Errorf("provider %q type %q does not support /v1/messages", providerName, pcfg.Type)
	}

	baseURL := resolveProviderBaseURL(pcfg)
	if baseURL == "" {
		return nil, fmt.Errorf("provider %q base_url is empty", providerName)
	}
	apiKey := resolveProviderAPIKey(pcfg)
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("provider %q api key missing", providerName)
	}

	targetURL := strings.TrimRight(baseURL, "/") + "/messages"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
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
		"x-api-key":         {},
		"X-Api-Key":         {},
		"anthropic-version": {},
		"Anthropic-Version": {},
	})
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	version := strings.TrimSpace(incoming.Get("anthropic-version"))
	if version == "" {
		version = defaultClaudeAPIVersion
	}
	req.Header.Set("anthropic-version", version)

	client := responsesHTTPClient()
	return client.Do(req)
}

func applyPostCheckToClaudeResponse(resp map[string]any, agg *postCheckAggregator) (int, error) {
	if resp == nil || agg == nil {
		return 0, nil
	}
	content, ok := resp["content"].([]any)
	if !ok || len(content) == 0 {
		return 0, nil
	}
	processed := 0
	for i := range content {
		seg, ok := content[i].(map[string]any)
		if !ok {
			continue
		}
		typ, _ := seg["type"].(string)
		if typ == "" {
			typ = "text"
		}
		if !isOutputContentType(typ) {
			if strings.EqualFold(typ, "tool_use") {
				inputVal, ok := seg["input"]
				if !ok {
					continue
				}
				updated, count, err := applyToStructuredStringLeaves(inputVal, func(_ string, text string) (string, error) {
					return agg.Check(text)
				}, "assistant")
				processed += count
				if err != nil {
					return processed, err
				}
				seg["input"] = updated
			}
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
	return processed, nil
}

func runPostCheckForClaudeStream(ctx context.Context, s *Server, infReq *inference.Request, capture *sseCapture) (string, string) {
	if infReq == nil || capture == nil || capture.truncated {
		if infReq != nil {
			infReq.PostDecision = "allow"
		}
		return "allow", ""
	}
	outputText := extractOutputTextFromClaudeSSE(capture.Bytes())
	if strings.TrimSpace(outputText) == "" {
		infReq.PostDecision = "allow"
		return "allow", ""
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
	return post.decision, outputText
}

func extractOutputTextFromClaudeSSE(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	payload := string(data)
	events := strings.Split(payload, "\n\n")
	var builder strings.Builder
	hasDelta := false
	for _, chunk := range events {
		event, evtData := parseSSEEvent(chunk)
		if strings.TrimSpace(evtData) == "" || evtData == "[DONE]" {
			continue
		}
		text, fromDelta := extractTextFromClaudeSSEData(event, evtData)
		if text == "" {
			continue
		}
		if fromDelta {
			builder.WriteString(text)
			hasDelta = true
			continue
		}
		if !hasDelta {
			builder.WriteString(text)
		}
	}
	return builder.String()
}

func extractTextFromClaudeSSEData(event, data string) (string, bool) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(data), &obj); err != nil {
		return "", false
	}

	if delta, ok := obj["delta"].(map[string]any); ok {
		if txt, ok := delta["text"].(string); ok {
			return txt, true
		}
		if partial, ok := delta["partial_json"].(string); ok {
			return partial, true
		}
	}
	if cb, ok := obj["content_block"].(map[string]any); ok {
		if txt, ok := cb["text"].(string); ok {
			return txt, false
		}
		if inputVal, ok := cb["input"]; ok {
			return extractStringLeaves(inputVal), false
		}
	}
	if msg, ok := obj["message"].(map[string]any); ok {
		if txt := extractOutputTextFromClaudeResponse(msg); txt != "" {
			return txt, false
		}
	}
	if txt, ok := obj["text"].(string); ok {
		return txt, event == "content_block_delta" || event == "message_delta"
	}
	return "", false
}

func extractOutputTextFromClaudeResponse(resp map[string]any) string {
	content, ok := resp["content"].([]any)
	if !ok {
		return ""
	}
	var builder strings.Builder
	for _, entry := range content {
		block, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := block["type"].(string)
		typ = strings.ToLower(strings.TrimSpace(typ))
		if typ == "" {
			typ = "text"
		}
		if strings.EqualFold(typ, "tool_use") {
			if inputVal, ok := block["input"]; ok {
				if s := extractStringLeaves(inputVal); s != "" {
					if builder.Len() > 0 {
						builder.WriteString("\n")
					}
					builder.WriteString(s)
				}
			}
			continue
		}
		if isOutputContentType(typ) {
			txt, ok := block["text"].(string)
			if !ok || txt == "" {
				continue
			}
			if builder.Len() > 0 {
				builder.WriteString("\n")
			}
			builder.WriteString(txt)
		}
	}
	return builder.String()
}

func applyToStructuredStringLeaves(value any, apply func(role, text string) (string, error), role string) (any, int, error) {
	switch v := value.(type) {
	case string:
		updated, err := apply(role, v)
		return updated, 1, err
	case []any:
		total := 0
		for i := range v {
			next, count, err := applyToStructuredStringLeaves(v[i], apply, role)
			if err != nil {
				return value, total + count, err
			}
			v[i] = next
			total += count
		}
		return v, total, nil
	case map[string]any:
		total := 0
		for k, raw := range v {
			next, count, err := applyToStructuredStringLeaves(raw, apply, role)
			if err != nil {
				return value, total + count, err
			}
			v[k] = next
			total += count
		}
		return v, total, nil
	default:
		return value, 0, nil
	}
}

func extractStringLeaves(value any) string {
	var parts []string
	collectStringLeaves(value, &parts)
	return strings.Join(parts, "\n")
}

func collectStringLeaves(value any, out *[]string) {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) != "" {
			*out = append(*out, v)
		}
	case []any:
		for _, item := range v {
			collectStringLeaves(item, out)
		}
	case map[string]any:
		for _, item := range v {
			collectStringLeaves(item, out)
		}
	}
}

type claudeErrorBody struct {
	Type  string            `json:"type"`
	Error claudeErrorDetail `json:"error"`
}

type claudeErrorDetail struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func writeClaudeError(w http.ResponseWriter, status int, message, typ string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(claudeErrorBody{
		Type: "error",
		Error: claudeErrorDetail{
			Type:    typ,
			Message: message,
		},
	})
}

func writeClaudePolicyBlockedError(w http.ResponseWriter, reason string) {
	if strings.TrimSpace(reason) == "" {
		reason = "Request blocked by Straja policy"
	}
	writeClaudeError(w, http.StatusForbidden, "Request blocked by Straja policy: "+reason, "invalid_request_error")
}
