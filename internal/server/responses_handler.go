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

	start := time.Now()
	ctx := r.Context()
	ctx, root := s.startSpan(ctx, "straja.request", trace.SpanKindServer, map[string]interface{}{
		"straja.version":                    version,
		"http.method":                       r.Method,
		"http.route":                        "/v1/responses",
		"straja.strajaguard.enabled":        s.strajaGuardModel != nil,
		"straja.strajaguard.loaded":         s.strajaGuardModel != nil,
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
		ProjectID: project.ID,
		Model:     model,
		Messages:  []inference.Message{},
		Timings:   &inference.Timings{},
	}
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
	if hasInput {
		var err error
		inputVal, infReq, _, _, err = s.hardenResponsesInput(ctx, project.ID, model, inputVal)
		if err != nil {
			decision = "blocked_before"
			statusCode = http.StatusForbidden
			s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionBlockedBefore)
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
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider)
		writeOpenAIError(w, http.StatusBadGateway, "Upstream provider error", "provider_error")
		return
	}
	defer upstreamResp.Body.Close()

	if upstreamResp.StatusCode >= 400 {
		decision = "error_provider"
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider)
	} else {
		decision = "allow"
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionAllow)
	}
	statusCode = upstreamResp.StatusCode

	if stream {
		setSSEHeaders(w.Header())
	} else {
		copyHeaders(w.Header(), upstreamResp.Header, nil)
	}
	w.WriteHeader(upstreamResp.StatusCode)

	if err := copyUpstreamBody(w, upstreamResp.Body, stream); err != nil && !errors.Is(err, context.Canceled) {
		cancel()
		redact.Logf("responses: streaming copy failed: %v", err)
	}
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
}

func hasPolicyDecision(decisions []safety.PolicyHit, category string) bool {
	for _, d := range decisions {
		if d.Category == category {
			return true
		}
	}
	return false
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
