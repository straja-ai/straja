package server

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/activation"
	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/redact"
	"github.com/straja-ai/straja/internal/safety"
	"github.com/straja-ai/straja/internal/toolgate"
	"go.opentelemetry.io/otel/trace"
)

type competitionMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type competitionCheckRequest struct {
	Conversation []competitionMessage `json:"conversation"`
}

type competitionCheckResponse struct {
	Violation  bool    `json:"violation"`
	Confidence float64 `json:"confidence"`
}

func (s *Server) handleCompetitionCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	start := time.Now()
	ctx := r.Context()
	ctx, root := s.startSpan(ctx, "straja.competition.check", trace.SpanKindServer, map[string]interface{}{
		"straja.version": version,
		"http.method":    r.Method,
		"http.route":     "/v1/competition/check",
	})
	defer root.End()

	s.applyGuardBodyLimit(w, r)

	var reqBody competitionCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		if isRequestTooLarge(err) {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "Request body too large", "invalid_request_error")
			return
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	messages, hasContent := normalizeCompetitionMessages(reqBody.Conversation)
	if len(messages) == 0 || !hasContent {
		http.Error(w, "conversation must include at least one non-empty message", http.StatusBadRequest)
		return
	}

	requestID := newRequestID()
	projectID := s.defaultProjectID()
	w.Header().Set("X-Straja-Request-Id", requestID)
	if s.requestStore != nil {
		s.requestStore.Start(requestID, projectID)
	}

	infReq := &inference.Request{
		RequestID: requestID,
		ProjectID: projectID,
		Model:     "competition_gsarena",
		Messages:  messages,
		Timings:   &inference.Timings{},
	}

	preStart := time.Now()
	preErr := s.policy.BeforeModel(ctx, infReq)
	if infReq.Timings != nil {
		infReq.Timings.PrePolicy = time.Since(preStart)
	}

	modelViolation, modelConfidence := competitionModelViolation(infReq.PolicyDecisions, infReq.SecurityScores)
	toolViolation, toolConfidence, toolHits := s.evaluateCompetitionToolcheck(messages)
	if len(toolHits) > 0 {
		infReq.PolicyDecisions = append(infReq.PolicyDecisions, toolgateHitsToPolicyHits(toolHits)...)
	}

	violation := modelViolation || toolViolation
	confidence := math.Max(modelConfidence, toolConfidence)
	if !violation {
		confidence = 0
	}
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}

	if preErr != nil && !violation {
		redact.Logf("competition: pre-policy blocked with non PI/JB categories only: %v", preErr)
	}

	decision := activation.DecisionAllow
	if violation {
		decision = activation.DecisionBlockedBefore
	}
	s.emitActivation(ctx, w, infReq, nil, "competition", decision, "competition_check")
	s.setActivationHeaderFromStore(w, requestID)

	resp := competitionCheckResponse{
		Violation:  violation,
		Confidence: confidence,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)

	_ = start
}

func normalizeCompetitionMessages(conversation []competitionMessage) ([]inference.Message, bool) {
	if len(conversation) == 0 {
		return nil, false
	}
	out := make([]inference.Message, 0, len(conversation))
	hasContent := false
	for _, msg := range conversation {
		role := normalizeRole(msg.Role)
		content := msg.Content
		if strings.TrimSpace(content) != "" {
			hasContent = true
		}
		out = append(out, inference.Message{Role: role, Content: content})
	}
	return out, hasContent
}

func competitionModelViolation(decisions []safety.PolicyHit, scores map[string]float32) (bool, float64) {
	categories := map[string]struct{}{
		"prompt_injection": {},
		"jailbreak":        {},
	}

	violation := false
	confidence := 0.0
	for _, hit := range decisions {
		category := strings.ToLower(strings.TrimSpace(hit.Category))
		if _, ok := categories[category]; !ok {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(hit.Action))
		if action == "allow" || action == "ignore" || action == "log" {
			continue
		}
		violation = true
		if c := float64(hit.Confidence); c > confidence {
			confidence = c
		}
	}

	for key, score := range scores {
		if _, ok := categories[strings.ToLower(strings.TrimSpace(key))]; !ok {
			continue
		}
		if s := float64(score); s > confidence {
			confidence = s
		}
	}

	if violation && confidence == 0 {
		confidence = 1
	}
	return violation, confidence
}

func (s *Server) evaluateCompetitionToolcheck(messages []inference.Message) (bool, float64, []toolgate.Hit) {
	candidates := competitionToolcheckCandidates(messages)
	if len(candidates) == 0 {
		return false, 0, nil
	}

	violation := false
	confidence := 0.0
	allHits := make([]toolgate.Hit, 0)
	for _, candidate := range candidates {
		res, _, _ := s.evaluateToolgate("shell.exec", map[string]any{"command": candidate}, "")
		if res.Action != toolgate.ActionAllow || len(res.Hits) > 0 {
			violation = true
		}
		if len(res.Hits) == 0 && res.Action != toolgate.ActionAllow {
			confidence = math.Max(confidence, 1)
		}
		for _, hit := range res.Hits {
			if c := float64(hit.Confidence); c > confidence {
				confidence = c
			}
		}
		allHits = append(allHits, res.Hits...)
	}

	return violation, confidence, allHits
}

func competitionToolcheckCandidates(messages []inference.Message) []string {
	userCommands := make([]string, 0, len(messages))
	fallback := make([]string, 0, len(messages))
	for _, msg := range messages {
		content := strings.TrimSpace(msg.Content)
		if content == "" {
			continue
		}
		fallback = append(fallback, content)
		if strings.EqualFold(strings.TrimSpace(msg.Role), "user") {
			userCommands = append(userCommands, content)
		}
	}
	if len(userCommands) > 0 {
		return userCommands
	}
	return fallback
}
