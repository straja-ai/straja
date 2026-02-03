package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/activation"
	guardapi "github.com/straja-ai/straja/internal/api/guard"
	"github.com/straja-ai/straja/internal/auth"
	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/redact"
	"github.com/straja-ai/straja/internal/responseguard"
	"github.com/straja-ai/straja/internal/safety"
	"go.opentelemetry.io/otel/trace"
)

const guardMaxBodyBytes = int64(1024 * 1024)

type guardErrorDetail struct {
	Message   string `json:"message"`
	Code      string `json:"code"`
	Category  string `json:"category"`
	RequestID string `json:"request_id"`
}

type guardErrorBody struct {
	Error guardErrorDetail `json:"error"`
}

func (s *Server) handleGuardRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	start := time.Now()
	ctx := r.Context()
	ctx, root := s.startSpan(ctx, "straja.guard.request", trace.SpanKindServer, map[string]interface{}{
		"straja.version": version,
		"http.method":    r.Method,
		"http.route":     "/v1/guard/request",
	})
	defer root.End()

	s.applyGuardBodyLimit(w, r)

	project, ok := s.guardAuthProject(w, r)
	if !ok {
		return
	}

	var reqBody guardapi.GuardRequestCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		if isRequestTooLarge(err) {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "Request body too large", "invalid_request_error")
			return
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(reqBody.InputText) == "" && len(reqBody.Messages) == 0 {
		http.Error(w, "missing input_text or messages", http.StatusBadRequest)
		return
	}

	projectID, ok := s.resolveGuardProject(w, project, reqBody.ProjectID)
	if !ok {
		return
	}

	requestID := strings.TrimSpace(reqBody.RequestID)
	if requestID == "" {
		requestID = newRequestID()
	}
	w.Header().Set("X-Straja-Request-Id", requestID)
	if s.requestStore != nil {
		s.requestStore.Start(requestID, projectID)
	}

	evalText, messages := buildGuardInput(reqBody)
	infReq := &inference.Request{
		RequestID: requestID,
		ProjectID: projectID,
		Model:     "guard_api",
		Messages:  messages,
		Timings:   &inference.Timings{},
	}
	if len(infReq.Messages) == 0 {
		infReq.Messages = []inference.Message{{Role: "user", Content: evalText}}
	}
	if s.loggingLevel == "full" && len(reqBody.ToolCalls) > 0 {
		infReq.ToolName = "tool_calls"
		infReq.ToolArgsPreview = guardToolCallsPreview(reqBody.ToolCalls)
	}

	preStart := time.Now()
	preErr := s.policy.BeforeModel(ctx, infReq)
	if infReq.Timings != nil {
		infReq.Timings.PrePolicy = time.Since(preStart)
	}

	decision := resolveGuardDecision(preErr, infReq.PolicyDecisions, infReq.Messages, evalText)
	sanitized := sanitizedTextForDecision(decision, infReq.Messages, evalText)
	redactions := guardRedactionsFromEntities(evalText, infReq.PIIEntities)

	policyHits := guardPolicyHitsFromDecisions(infReq.PolicyDecisions, reqBody.InputText, evalText, true)
	reasons := guardReasonsFromSignalsAndHits(infReq.DetectionSignals, infReq.PolicyDecisions, true)
	strajaGuard := guardStrajaGuardInfo(s, infReq, true)

	resp := guardapi.GuardRequestCheckResponse{
		RequestID:     requestID,
		Decision:      decision,
		Action:        actionForDecision(decision),
		Redactions:    redactions,
		SanitizedText: sanitized,
		Reasons:       reasons,
		PolicyHits:    policyHits,
		StrajaGuard:   strajaGuard,
	}

	actDecision := activation.DecisionAllow
	if decision == "block" {
		actDecision = activation.DecisionBlockedBefore
	}
	s.emitActivation(ctx, w, infReq, nil, "guard_api", actDecision, "guard_api")
	s.setActivationHeaderFromStore(w, requestID)

	if decision == "block" {
		writeGuardBlockedError(w, requestID, "Request blocked by policy.", reasons, policyHits)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)

	_ = start
}

func (s *Server) handleGuardResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	start := time.Now()
	ctx := r.Context()
	ctx, root := s.startSpan(ctx, "straja.guard.response", trace.SpanKindServer, map[string]interface{}{
		"straja.version": version,
		"http.method":    r.Method,
		"http.route":     "/v1/guard/response",
	})
	defer root.End()

	s.applyGuardBodyLimit(w, r)

	project, ok := s.guardAuthProject(w, r)
	if !ok {
		return
	}

	var reqBody guardapi.GuardResponseCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		if isRequestTooLarge(err) {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "Request body too large", "invalid_request_error")
			return
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	requestID := strings.TrimSpace(reqBody.RequestID)
	if requestID == "" {
		http.Error(w, "missing request_id", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(reqBody.OutputText) == "" {
		http.Error(w, "missing output_text", http.StatusBadRequest)
		return
	}

	projectID := project.ID
	if projectID == "" {
		projectID = s.defaultProjectID()
	}
	if s.requestStore != nil {
		s.requestStore.Start(requestID, projectID)
	}

	infReq := &inference.Request{
		RequestID: requestID,
		ProjectID: projectID,
		Model:     "guard_api",
		Messages:  nil,
		Timings:   &inference.Timings{},
	}

	outputText := reqBody.OutputText
	updated, post := s.postCheckText(ctx, infReq, outputText)
	infReq.PostPolicyHits = post.postReq.PolicyHits
	infReq.PostPolicyDecisions = post.postReq.PolicyDecisions
	infReq.PostDecision = post.decision
	infReq.OutputPreview = outputPreview(post.outputs)
	infReq.PostCheckLatency = post.latency
	infReq.PostSafetyScores = post.postReq.SecurityScores
	infReq.PostSafetyFlags = post.postReq.SecurityFlags

	resGuard := s.applyResponseGuard(infReq, s.evaluateResponseGuard(outputText), false)

	decision := resolveGuardPostDecision(post, resGuard)
	sanitized := sanitizedTextForPostDecision(decision, updated, outputText)
	redactions := guardRedactionsFromEntities(outputText, nil)
	policyHits := guardPolicyHitsFromDecisions(infReq.PostPolicyDecisions, "", outputText, false)
	policyHits = append(policyHits, guardPolicyHitsFromResponseGuard(resGuard)...)
	reasons := guardReasonsFromSignalsAndHits(infReq.DetectionSignals, infReq.PostPolicyDecisions, false)
	reasons = append(reasons, guardReasonsFromResponseGuard(resGuard)...)
	strajaGuard := guardStrajaGuardInfo(s, infReq, false)

	resp := guardapi.GuardResponseCheckResponse{
		RequestID:     requestID,
		Decision:      decision,
		Action:        actionForDecision(decision),
		Redactions:    redactions,
		SanitizedText: sanitized,
		Reasons:       normalizeReasons(reasons),
		PolicyHits:    normalizePolicyHits(policyHits),
		StrajaGuard:   strajaGuard,
	}

	actDecision := activation.DecisionAllow
	if decision == "block" {
		actDecision = activation.DecisionBlockedAfter
	}
	s.emitActivation(ctx, w, infReq, &inference.Response{Message: inference.Message{Role: "assistant", Content: outputText}}, "guard_api", actDecision, "guard_api")
	s.setActivationHeaderFromStore(w, requestID)

	if decision == "block" {
		writeGuardBlockedError(w, requestID, "Response blocked by policy.", reasons, policyHits)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)

	_ = start
}

func (s *Server) applyGuardBodyLimit(w http.ResponseWriter, r *http.Request) {
	if w == nil || r == nil {
		return
	}
	limit := guardMaxBodyBytes
	if s.cfg.Server.MaxRequestBodyBytes > 0 && s.cfg.Server.MaxRequestBodyBytes < limit {
		limit = s.cfg.Server.MaxRequestBodyBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
}

func (s *Server) guardAuthProject(w http.ResponseWriter, r *http.Request) (auth.Project, bool) {
	if s.cfg.Security.GuardAPI.RequireAuth {
		project, ok := s.resolveAuthProjectBearerOnly(r)
		if !ok {
			writeOpenAIError(w, http.StatusUnauthorized, "Invalid or missing API key", "authentication_error")
			return auth.Project{}, false
		}
		return project, true
	}
	return auth.Project{}, true
}

func (s *Server) resolveAuthProjectBearerOnly(r *http.Request) (auth.Project, bool) {
	apiKey, ok := parseBearerToken(r.Header.Get("Authorization"))
	if !ok || apiKey == "" {
		return auth.Project{}, false
	}
	project, ok := s.auth.Lookup(apiKey)
	if !ok {
		return auth.Project{}, false
	}
	return project, true
}

func (s *Server) resolveGuardProject(w http.ResponseWriter, project auth.Project, requestProjectID string) (string, bool) {
	projectID := project.ID
	if strings.TrimSpace(requestProjectID) != "" {
		if _, ok := s.projectProviders[requestProjectID]; !ok {
			http.Error(w, "unknown project_id", http.StatusBadRequest)
			return "", false
		}
		if projectID != "" && projectID != requestProjectID {
			writeOpenAIError(w, http.StatusForbidden, "project_id does not match API key", "authentication_error")
			return "", false
		}
		projectID = requestProjectID
	}
	if projectID == "" {
		projectID = s.defaultProjectID()
	}
	return projectID, true
}

func (s *Server) defaultProjectID() string {
	if len(s.cfg.Projects) > 0 {
		return s.cfg.Projects[0].ID
	}
	return ""
}

func buildGuardInput(req guardapi.GuardRequestCheckRequest) (string, []inference.Message) {
	var messages []inference.Message
	if strings.TrimSpace(req.InputText) != "" {
		if len(req.Messages) > 0 {
			messages = make([]inference.Message, 0, len(req.Messages)+1)
			for _, m := range req.Messages {
				role := normalizeRole(m.Role)
				messages = append(messages, inference.Message{Role: role, Content: m.Content})
			}
		}
		messages = append(messages, inference.Message{Role: "user", Content: req.InputText})
		return req.InputText, messages
	}
	if len(req.Messages) > 0 {
		messages = make([]inference.Message, 0, len(req.Messages)+1)
		for _, m := range req.Messages {
			role := normalizeRole(m.Role)
			messages = append(messages, inference.Message{Role: role, Content: m.Content})
		}
		joined := joinGuardMessages(req.Messages)
		messages = append(messages, inference.Message{Role: "user", Content: joined})
		return joined, messages
	}
	return req.InputText, []inference.Message{{Role: "user", Content: req.InputText}}
}

func joinGuardMessages(msgs []guardapi.Message) string {
	var b strings.Builder
	for i, m := range msgs {
		if i > 0 {
			b.WriteString("\n")
		}
		role := normalizeRole(m.Role)
		b.WriteString("[")
		b.WriteString(role)
		b.WriteString("]: ")
		b.WriteString(m.Content)
	}
	return b.String()
}

func resolveGuardDecision(preErr error, decisions []safety.PolicyHit, msgs []inference.Message, evalText string) string {
	if preErr != nil {
		return "block"
	}
	if hasAction(decisions, "block") {
		return "block"
	}
	if hasAction(decisions, "redact") || hasAction(decisions, "block_and_redact") {
		return "redact"
	}
	if redacted := hasRedaction(msgs, evalText); redacted {
		return "redact"
	}
	if hasAction(decisions, "warn") {
		return "warn"
	}
	return "allow"
}

func resolveGuardPostDecision(post postCheckResult, resGuard responseguard.Result) string {
	if hasAction(post.postReq.PolicyDecisions, "block") {
		return "block"
	}
	if post.decision == "redacted" {
		return "redact"
	}
	if resGuard.Decision == "warn" || hasAction(post.postReq.PolicyDecisions, "warn") {
		return "warn"
	}
	return "allow"
}

func hasAction(decisions []safety.PolicyHit, action string) bool {
	for _, hit := range decisions {
		if strings.EqualFold(strings.TrimSpace(hit.Action), action) {
			return true
		}
	}
	return false
}

func hasRedaction(msgs []inference.Message, evalText string) bool {
	if len(msgs) == 0 {
		return false
	}
	last := msgs[len(msgs)-1].Content
	return last != evalText
}

func sanitizedTextForDecision(decision string, msgs []inference.Message, evalText string) *string {
	if decision != "redact" {
		return nil
	}
	if len(msgs) == 0 {
		out := evalText
		return &out
	}
	out := msgs[len(msgs)-1].Content
	return &out
}

func sanitizedTextForPostDecision(decision, updated, original string) *string {
	if decision != "redact" {
		return nil
	}
	if updated == "" {
		updated = original
	}
	return &updated
}

func actionForDecision(decision string) string {
	switch decision {
	case "redact":
		return "modify"
	case "warn", "allow":
		return "allow"
	case "block":
		return "block"
	default:
		return "allow"
	}
}

func writeGuardBlockedError(
	w http.ResponseWriter,
	requestID string,
	fallbackMessage string,
	reasons []guardapi.Reason,
	policyHits []guardapi.PolicyHit,
) {
	message := strings.TrimSpace(fallbackMessage)
	category := "policy"
	if len(reasons) > 0 {
		if strings.TrimSpace(reasons[0].Rule) != "" {
			message = reasons[0].Rule
		}
		if strings.TrimSpace(reasons[0].Category) != "" {
			category = reasons[0].Category
		}
	}
	if len(policyHits) > 0 {
		if message == "" && strings.TrimSpace(policyHits[0].Details) != "" {
			message = policyHits[0].Details
		}
		if category == "policy" && strings.TrimSpace(policyHits[0].Category) != "" {
			category = policyHits[0].Category
		}
	}
	if message == "" {
		message = "Blocked by guard policy."
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(guardErrorBody{
		Error: guardErrorDetail{
			Message:   message,
			Code:      "guard_blocked",
			Category:  category,
			RequestID: requestID,
		},
	})
}

func guardRedactionsFromEntities(text string, entities []safety.PIIEntity) []guardapi.Redaction {
	if text == "" || len(entities) == 0 {
		return nil
	}
	out := make([]guardapi.Redaction, 0, len(entities))
	for _, e := range entities {
		if e.StartByte < 0 || e.EndByte <= e.StartByte || e.EndByte > len(text) {
			continue
		}
		out = append(out, guardapi.Redaction{
			Type:        "pii",
			Start:       e.StartByte,
			End:         e.EndByte,
			Replacement: "[REDACTED]",
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func guardPolicyHitsFromDecisions(decisions []safety.PolicyHit, inputText, evalText string, isRequest bool) []guardapi.PolicyHit {
	if len(decisions) == 0 {
		return nil
	}
	out := make([]guardapi.PolicyHit, 0, len(decisions))
	for _, hit := range decisions {
		details := strings.TrimSpace(hit.Evidence)
		if details == "" && len(hit.Sources) > 0 {
			details = strings.Join(hit.Sources, ",")
		}
		if details == "" && inputText != "" && inputText != evalText {
			preview := guardTruncate(inputText, 120)
			details = "input_text=" + redact.String(preview)
		}
		out = append(out, guardapi.PolicyHit{
			Category: mapGuardCategory(hit.Category, isRequest),
			Action:   normalizeGuardAction(hit.Action),
			Details:  details,
		})
	}
	return out
}

func guardPolicyHitsFromResponseGuard(res responseguard.Result) []guardapi.PolicyHit {
	if len(res.Hits) == 0 {
		return nil
	}
	out := make([]guardapi.PolicyHit, 0, len(res.Hits))
	for _, hit := range res.Hits {
		out = append(out, guardapi.PolicyHit{
			Category: mapGuardCategory(hit.Category, false),
			Action:   normalizeGuardAction(hit.Action),
			Details:  hit.Evidence,
		})
	}
	return out
}

func guardReasonsFromSignalsAndHits(signals []safety.DetectionSignal, decisions []safety.PolicyHit, isRequest bool) []guardapi.Reason {
	seen := map[string]struct{}{}
	out := make([]guardapi.Reason, 0, len(decisions)+len(signals))
	for _, hit := range decisions {
		cat := mapGuardCategory(hit.Category, isRequest)
		key := cat + "|" + hit.Action
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, guardapi.Reason{
			Category:   cat,
			Rule:       ruleFromHit(hit),
			Severity:   severityFromAction(hit.Action),
			Confidence: float64(hit.Confidence),
		})
	}
	for _, sig := range signals {
		cat := mapGuardCategory(sig.Category, isRequest)
		key := cat + "|" + sig.Source
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, guardapi.Reason{
			Category:   cat,
			Rule:       sig.Source,
			Severity:   severityFromConfidence(sig.Confidence),
			Confidence: float64(sig.Confidence),
		})
	}
	return out
}

func guardReasonsFromResponseGuard(res responseguard.Result) []guardapi.Reason {
	if len(res.Hits) == 0 {
		return nil
	}
	out := make([]guardapi.Reason, 0, len(res.Hits))
	for _, hit := range res.Hits {
		out = append(out, guardapi.Reason{
			Category:   mapGuardCategory(hit.Category, false),
			Rule:       hit.RuleID,
			Severity:   severityFromAction(hit.Action),
			Confidence: float64(hit.Confidence),
		})
	}
	return out
}

func normalizeReasons(reasons []guardapi.Reason) []guardapi.Reason {
	if len(reasons) == 0 {
		return nil
	}
	out := make([]guardapi.Reason, 0, len(reasons))
	seen := map[string]struct{}{}
	for _, r := range reasons {
		key := r.Category + "|" + r.Rule
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	return out
}

func normalizePolicyHits(hits []guardapi.PolicyHit) []guardapi.PolicyHit {
	if len(hits) == 0 {
		return nil
	}
	out := make([]guardapi.PolicyHit, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		key := h.Category + "|" + h.Action + "|" + h.Details
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, h)
	}
	return out
}

func mapGuardCategory(category string, isRequest bool) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "prompt_injection":
		return "prompt_injection"
	case "jailbreak":
		return "jailbreak"
	case "pii", "contains_personal_data":
		return "pii"
	case responseguard.CategoryDataExfilInstruction:
		return "data_exfil"
	case responseguard.CategoryUnsafeActionInstruction, responseguard.CategoryPrivilegeEscalationInstruction:
		return "data_exfil"
	default:
		if isRequest {
			return "other"
		}
		return "other"
	}
}

func normalizeGuardAction(action string) string {
	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "block", "block_and_redact":
		return "block"
	case "redact", "redacted":
		return "redact"
	case "warn":
		return "warn"
	case "allow", "log", "ignore":
		return "allow"
	default:
		return "allow"
	}
}

func ruleFromHit(hit safety.PolicyHit) string {
	if hit.Evidence != "" {
		return hit.Evidence
	}
	if len(hit.Sources) > 0 {
		return hit.Sources[0]
	}
	return hit.Category
}

func severityFromAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "block_and_redact":
		return "high"
	case "redact", "redacted":
		return "medium"
	case "warn":
		return "low"
	default:
		return "low"
	}
}

func severityFromConfidence(conf float32) string {
	if conf >= 0.8 {
		return "high"
	}
	if conf >= 0.5 {
		return "medium"
	}
	return "low"
}

func guardStrajaGuardInfo(s *Server, req *inference.Request, isRequest bool) guardapi.StrajaGuardInfo {
	if s == nil || !s.strajaGuardEnabled() {
		return guardapi.StrajaGuardInfo{Enabled: false}
	}
	labels := []string{}
	score := 0.0
	if req != nil {
		var scores map[string]float32
		var flags []string
		if isRequest {
			scores = req.SecurityScores
			flags = req.SecurityFlags
		} else {
			scores = req.PostSafetyScores
			flags = req.PostSafetyFlags
		}
		for _, v := range scores {
			if float64(v) > score {
				score = float64(v)
			}
		}
		if len(flags) > 0 {
			labels = append(labels, flags...)
		}
	}
	if s.requireML {
		labels = append(labels, "ml_required")
	}
	if s.allowRegexOnly {
		labels = append(labels, "regex_only")
	}
	if len(labels) == 0 {
		labels = nil
	}
	info := guardapi.StrajaGuardInfo{
		Enabled:      true,
		ModelVersion: s.strajaGuardFamily,
		Score:        score,
		Labels:       labels,
	}
	return info
}

func guardToolCallsPreview(calls []guardapi.ToolCall) string {
	if len(calls) == 0 {
		return ""
	}
	b, err := json.Marshal(calls)
	if err != nil {
		return ""
	}
	return guardTruncate(string(b), 500)
}

func guardTruncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
