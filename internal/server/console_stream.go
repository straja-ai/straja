package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
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

	apiKey := s.projectAPIKey(reqBody.ProjectID)
	if apiKey == "" {
		return errConsoleMissingAPIKey
	}

	payload := map[string]any{
		"model":  reqBody.Model,
		"input":  responsesInputFromMessages(reqBody.Messages),
		"stream": true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "/v1/responses", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	s.handleResponses(w, req)
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
