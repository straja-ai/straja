package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/straja-ai/straja-gateway/internal/activation"
	"github.com/straja-ai/straja-gateway/internal/inference"
	"github.com/straja-ai/straja-gateway/internal/redact"
	"github.com/straja-ai/straja-gateway/internal/safety"
	"github.com/straja-ai/straja-gateway/internal/toolgate"
	"go.opentelemetry.io/otel/trace"
)

type toolgateCheckContext struct {
	ProjectID string `json:"project_id"`
	Mode      string `json:"mode"`
	Source    string `json:"source"`
}

type toolgateCheckRequest struct {
	ToolName string               `json:"tool_name"`
	Args     map[string]any       `json:"args"`
	Context  toolgateCheckContext `json:"context"`
}

type toolgateNormalized struct {
	Available bool   `json:"available"`
	Command   string `json:"command"`
}

type toolgateCheckResponse struct {
	RequestID  string             `json:"request_id"`
	Decision   string             `json:"decision"`
	Hits       []toolgate.Hit     `json:"hits,omitempty"`
	Normalized toolgateNormalized `json:"normalized"`
	LatencyMs  float64            `json:"latency_ms"`
}

type toolgateExplainHit struct {
	RuleID       string `json:"rule_id"`
	Category     string `json:"category"`
	Action       string `json:"action"`
	MatchedOn    string `json:"matched_on"`
	EvidenceSpan [2]int `json:"evidence_span"`
}

type toolgateExplainResponse struct {
	RequestID  string               `json:"request_id"`
	Decision   string               `json:"decision"`
	Hits       []toolgateExplainHit `json:"hits,omitempty"`
	Normalized toolgateNormalized   `json:"normalized"`
	LatencyMs  float64              `json:"latency_ms"`
}

type toolgateErrorDetail struct {
	Message   string `json:"message"`
	Type      string `json:"type"`
	Code      string `json:"code"`
	RuleID    string `json:"rule_id,omitempty"`
	Category  string `json:"category,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

type toolgateErrorBody struct {
	Error toolgateErrorDetail `json:"error"`
}

func (s *Server) handleToolgateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	start := time.Now()
	ctx := r.Context()
	ctx, root := s.startSpan(ctx, "straja.toolgate.check", trace.SpanKindServer, map[string]interface{}{
		"straja.version": version,
		"http.method":    r.Method,
		"http.route":     "/v1/toolgate/check",
	})
	defer root.End()

	if s.cfg.Server.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Server.MaxRequestBodyBytes)
	}

	project, _, ok := s.resolveAuthProject(r)
	if !ok {
		writeOpenAIError(w, http.StatusUnauthorized, "Invalid or missing API key", "authentication_error")
		return
	}

	var reqBody toolgateCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		if isRequestTooLarge(err) {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "Request body too large", "invalid_request_error")
			return
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(reqBody.ToolName) == "" {
		http.Error(w, "missing tool_name", http.StatusBadRequest)
		return
	}

	projectID := project.ID
	if reqBody.Context.ProjectID != "" {
		if _, ok := s.projectProviders[reqBody.Context.ProjectID]; !ok {
			http.Error(w, "unknown project_id", http.StatusBadRequest)
			return
		}
		if reqBody.Context.ProjectID != project.ID {
			writeOpenAIError(w, http.StatusForbidden, "project_id does not match API key", "authentication_error")
			return
		}
		projectID = reqBody.Context.ProjectID
	}

	mode := strings.TrimSpace(reqBody.Context.Mode)
	if mode != "" {
		mode = strings.ToLower(mode)
		if mode != string(toolgate.ModeElevatedOnly) && mode != string(toolgate.ModeAllTools) {
			http.Error(w, "invalid mode", http.StatusBadRequest)
			return
		}
	}

	requestID := newRequestID()
	w.Header().Set("X-Straja-Request-Id", requestID)
	if s.requestStore != nil {
		s.requestStore.Start(requestID, projectID)
	}

	res, normalized, latency := s.evaluateToolgate(reqBody.ToolName, reqBody.Args, mode)

	infReq := &inference.Request{
		RequestID:       requestID,
		ProjectID:       projectID,
		Model:           "toolgate",
		ToolName:        reqBody.ToolName,
		ToolArgsPreview: buildToolArgsPreview(reqBody.Args),
		Timings:         &inference.Timings{PrePolicy: time.Since(start)},
	}
	infReq.PolicyDecisions = toolgateHitsToPolicyHits(res.Hits)
	infReq.PolicyHits = policyHitCategories(infReq.PolicyDecisions)

	decision := activation.DecisionAllow
	if res.Action == toolgate.ActionBlock {
		decision = activation.DecisionBlockedBefore
	}
	s.emitActivation(ctx, w, infReq, nil, "toolgate", decision, "toolgate_check")
	s.setActivationHeaderFromStore(w, requestID)

	if res.Action == toolgate.ActionBlock {
		writeToolgateBlockedError(w, requestID, res.Hits)
		return
	}

	resp := toolgateCheckResponse{
		RequestID:  requestID,
		Decision:   string(res.Action),
		Hits:       res.Hits,
		Normalized: normalized,
		LatencyMs:  latency,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleToolgateExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.cfg.ToolGateAPI.AllowExplain {
		writeOpenAIError(w, http.StatusForbidden, "toolgate explain disabled", "invalid_request_error")
		return
	}

	start := time.Now()
	ctx := r.Context()
	ctx, root := s.startSpan(ctx, "straja.toolgate.explain", trace.SpanKindServer, map[string]interface{}{
		"straja.version": version,
		"http.method":    r.Method,
		"http.route":     "/v1/toolgate/explain",
	})
	defer root.End()

	if s.cfg.Server.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Server.MaxRequestBodyBytes)
	}

	project, _, ok := s.resolveAuthProject(r)
	if !ok {
		writeOpenAIError(w, http.StatusUnauthorized, "Invalid or missing API key", "authentication_error")
		return
	}

	var reqBody toolgateCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		if isRequestTooLarge(err) {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "Request body too large", "invalid_request_error")
			return
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(reqBody.ToolName) == "" {
		http.Error(w, "missing tool_name", http.StatusBadRequest)
		return
	}

	projectID := project.ID
	if reqBody.Context.ProjectID != "" {
		if _, ok := s.projectProviders[reqBody.Context.ProjectID]; !ok {
			http.Error(w, "unknown project_id", http.StatusBadRequest)
			return
		}
		if reqBody.Context.ProjectID != project.ID {
			writeOpenAIError(w, http.StatusForbidden, "project_id does not match API key", "authentication_error")
			return
		}
		projectID = reqBody.Context.ProjectID
	}

	mode := strings.TrimSpace(reqBody.Context.Mode)
	if mode != "" {
		mode = strings.ToLower(mode)
		if mode != string(toolgate.ModeElevatedOnly) && mode != string(toolgate.ModeAllTools) {
			http.Error(w, "invalid mode", http.StatusBadRequest)
			return
		}
	}

	requestID := newRequestID()
	w.Header().Set("X-Straja-Request-Id", requestID)
	if s.requestStore != nil {
		s.requestStore.Start(requestID, projectID)
	}

	res, normalized, explain, latency := s.evaluateToolgateExplain(reqBody.ToolName, reqBody.Args, mode)

	infReq := &inference.Request{
		RequestID:       requestID,
		ProjectID:       projectID,
		Model:           "toolgate",
		ToolName:        reqBody.ToolName,
		ToolArgsPreview: buildToolArgsPreview(reqBody.Args),
		Timings:         &inference.Timings{PrePolicy: time.Since(start)},
	}
	infReq.PolicyDecisions = toolgateHitsToPolicyHits(res.Hits)
	infReq.PolicyHits = policyHitCategories(infReq.PolicyDecisions)

	decision := activation.DecisionAllow
	if res.Action == toolgate.ActionBlock {
		decision = activation.DecisionBlockedBefore
	}
	s.emitActivation(ctx, w, infReq, nil, "toolgate", decision, "toolgate_check")
	s.setActivationHeaderFromStore(w, requestID)

	if res.Action == toolgate.ActionBlock {
		writeToolgateBlockedError(w, requestID, res.Hits)
		return
	}

	respHits := make([]toolgateExplainHit, 0, len(explain.Hits))
	for _, hit := range explain.Hits {
		respHits = append(respHits, toolgateExplainHit{
			RuleID:       hit.RuleID,
			Category:     hit.Category,
			Action:       hit.Action,
			MatchedOn:    hit.MatchedOn,
			EvidenceSpan: hit.EvidenceSpan,
		})
	}

	resp := toolgateExplainResponse{
		RequestID:  requestID,
		Decision:   string(res.Action),
		Hits:       respHits,
		Normalized: normalized,
		LatencyMs:  latency,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func inferToolTypeFromRequest(name string, args map[string]any) toolgate.ToolType {
	tool := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(tool, "filesystem.") {
		return toolgate.ToolTypeFilesystem
	}
	if strings.HasPrefix(tool, "http") {
		return toolgate.ToolTypeHTTP
	}
	if strings.Contains(tool, "shell") || tool == "bash" || tool == "sh" {
		return toolgate.ToolTypeShell
	}
	if tool == "nodes.run" {
		if v, ok := getStringArg(args, "tool_type"); ok {
			return toolgate.ToolType(strings.ToLower(v))
		}
	}
	return ""
}

func extractShellCommandFromArgs(args map[string]any) string {
	if v, ok := getStringArg(args, "command"); ok {
		return v
	}
	if v, ok := getStringArg(args, "cmd"); ok {
		return v
	}
	if v, ok := getStringArg(args, "shell_command"); ok {
		return v
	}
	return ""
}

func (s *Server) evaluateToolgate(toolName string, args map[string]any, mode string) (toolgate.Result, toolgateNormalized, float64) {
	start := time.Now()
	tgCfg := s.cfg.ToolGate
	if mode != "" {
		tgCfg.Mode = mode
	}
	call := toolgate.ToolCall{
		Name: strings.TrimSpace(toolName),
		Type: inferToolTypeFromRequest(toolName, args),
		Args: args,
	}

	command := extractShellCommandFromArgs(args)
	normalized := toolgateNormalized{Available: false}
	if call.Type == toolgate.ToolTypeShell && strings.TrimSpace(command) != "" {
		normalized.Available = true
		normalized.Command = redact.String(toolgate.NormalizeShellCommand(command))
	}

	evaluator := toolgate.New(tgCfg)
	res := evaluator.Evaluate(call)
	latency := float64(time.Since(start).Milliseconds())
	return res, normalized, latency
}

func (s *Server) evaluateToolgateExplain(toolName string, args map[string]any, mode string) (toolgate.Result, toolgateNormalized, toolgate.ExplainResult, float64) {
	start := time.Now()
	tgCfg := s.cfg.ToolGate
	if mode != "" {
		tgCfg.Mode = mode
	}
	call := toolgate.ToolCall{
		Name: strings.TrimSpace(toolName),
		Type: inferToolTypeFromRequest(toolName, args),
		Args: args,
	}

	command := extractShellCommandFromArgs(args)
	normalized := toolgateNormalized{Available: false}
	if call.Type == toolgate.ToolTypeShell && strings.TrimSpace(command) != "" {
		normalized.Available = true
		normalized.Command = redact.String(toolgate.NormalizeShellCommand(command))
	}

	evaluator := toolgate.New(tgCfg)
	res, explain := evaluator.Explain(call)
	latency := float64(time.Since(start).Milliseconds())
	return res, normalized, explain, latency
}

func buildToolArgsPreview(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	b, err := json.Marshal(args)
	if err != nil {
		return redact.String(fmt.Sprintf("%v", args))
	}
	preview := redact.String(string(b))
	if len(preview) <= 120 {
		return preview
	}
	return preview[:120]
}

func toolgateHitsToPolicyHits(hits []toolgate.Hit) []safety.PolicyHit {
	if len(hits) == 0 {
		return nil
	}
	out := make([]safety.PolicyHit, 0, len(hits))
	for _, h := range hits {
		out = append(out, safety.PolicyHit{
			Category:   h.Category,
			Action:     h.Action,
			Confidence: h.Confidence,
			Sources:    h.Sources,
			Evidence:   h.Evidence,
		})
	}
	return out
}

func policyHitCategories(hits []safety.PolicyHit) []string {
	if len(hits) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	for _, hit := range hits {
		cat := strings.TrimSpace(hit.Category)
		if cat == "" {
			continue
		}
		seen[cat] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for cat := range seen {
		out = append(out, cat)
	}
	return out
}

func writeToolgateBlockedError(w http.ResponseWriter, requestID string, hits []toolgate.Hit) {
	first := toolgate.Hit{}
	if len(hits) > 0 {
		first = hits[0]
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(toolgateErrorBody{
		Error: toolgateErrorDetail{
			Message:   "Tool execution blocked by Straja toolgate",
			Type:      "straja_tool_policy_violation",
			Code:      "tool_blocked",
			RuleID:    first.RuleID,
			Category:  first.Category,
			RequestID: requestID,
		},
	})
}

func (s *Server) setActivationHeaderFromStore(w http.ResponseWriter, requestID string) {
	if w == nil || s.requestStore == nil || requestID == "" {
		return
	}
	entry, ok := s.requestStore.Get(requestID)
	if !ok || entry.activation == nil {
		return
	}
	if b, err := json.Marshal(entry.activation); err == nil {
		w.Header().Set("X-Straja-Activation", redact.String(string(b)))
	}
}

func getStringArg(args map[string]any, key string) (string, bool) {
	if args == nil {
		return "", false
	}
	val, ok := args[key]
	if !ok || val == nil {
		return "", false
	}
	switch v := val.(type) {
	case string:
		return v, true
	default:
		return fmt.Sprintf("%v", v), true
	}
}
