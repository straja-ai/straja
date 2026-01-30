package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/activation"
	"github.com/straja-ai/straja/internal/redact"
)

var errConsoleMissingAPIKey = errors.New("project has no api_keys configured for streaming")

func parseBoolQuery(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "t", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func (s *Server) handleConsoleChatStream(w http.ResponseWriter, r *http.Request, reqBody consoleChatRequest) error {
	setConsoleRobotsHeader(w)

	requestID := newRequestID()
	w.Header().Set("X-Straja-Request-Id", requestID)

	ctx := r.Context()
	var cancel context.CancelFunc
	if s.cfg.Server.UpstreamTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, s.cfg.Server.UpstreamTimeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	if s.projectAPIKey(reqBody.ProjectID) == "" {
		return errConsoleMissingAPIKey
	}

	providerName := s.projectProviders[reqBody.ProjectID]
	if providerName == "" {
		providerName = s.defaultProvider
	}
	provCfg, ok := s.cfg.Providers[providerName]
	if !ok {
		return errors.New("unknown provider for project")
	}

	inputVal := responsesInputFromMessages(reqBody.Messages)
	sanitized, infReq, _, _, err := s.hardenResponsesInput(ctx, reqBody.ProjectID, reqBody.Model, inputVal)
	infReq.RequestID = requestID
	if err != nil {
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionBlockedBefore)
		writePolicyBlockedError(w, http.StatusForbidden, err.Error())
		return nil
	}
	s.requestStore.Start(requestID, reqBody.ProjectID)

	payload := map[string]any{
		"model":  reqBody.Model,
		"input":  sanitized,
		"stream": true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	providerStart := time.Now()
	upstreamResp, err := s.doResponsesUpstream(ctx, provCfg, providerName, http.Header{}, body)
	if infReq.Timings != nil {
		infReq.Timings.Provider = time.Since(providerStart)
	}
	if err != nil {
		redact.Logf("provider %q error (console stream): %v", providerName, err)
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider)
		writeOpenAIError(w, http.StatusBadGateway, "Upstream provider error", "provider_error")
		return nil
	}
	defer upstreamResp.Body.Close()

	if upstreamResp.StatusCode >= 400 {
		copyHeaders(w.Header(), upstreamResp.Header, nil)
		w.WriteHeader(upstreamResp.StatusCode)
		_, _ = io.Copy(w, upstreamResp.Body)
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider)
		return nil
	}

	setSSEHeaders(w.Header())
	w.WriteHeader(upstreamResp.StatusCode)
	capture := newSSECapture(s.cfg.Server.MaxNonStreamResponseBytes)
	if err := copyUpstreamBodyWithCapture(w, upstreamResp.Body, capture); err != nil && !errors.Is(err, context.Canceled) {
		cancel()
		redact.Logf("console stream copy failed: %v", err)
	}
	postDecision := runPostCheckForStream(ctx, s, infReq, capture)
	if postDecision == "blocked" {
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionBlockedAfter)
	} else {
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionAllow)
	}
	return nil
}

func (s *Server) projectAPIKey(projectID string) string {
	for _, p := range s.cfg.Projects {
		if p.ID == projectID {
			if len(p.APIKeys) > 0 {
				return strings.TrimSpace(p.APIKeys[0])
			}
			return ""
		}
	}
	return ""
}

func responsesInputFromMessages(msgs []chatMessage) []any {
	out := make([]any, 0, len(msgs))
	for _, m := range msgs {
		role := strings.TrimSpace(m.Role)
		if role == "" {
			role = "user"
		}
		out = append(out, map[string]any{
			"role": role,
			"content": []map[string]any{
				{
					"type": "input_text",
					"text": m.Content,
				},
			},
		})
	}
	return out
}
