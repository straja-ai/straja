package server

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (s *Server) handleRequestStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestID := strings.TrimPrefix(r.URL.Path, "/v1/straja/requests/")
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		http.NotFound(w, r)
		return
	}

	apiKey, ok := parseBearerToken(r.Header.Get("Authorization"))
	if !ok || apiKey == "" {
		writeOpenAIError(w, http.StatusUnauthorized, "Invalid or missing API key", "authentication_error")
		return
	}

	project, ok := s.auth.Lookup(apiKey)
	if !ok {
		writeOpenAIError(w, http.StatusUnauthorized, "Invalid API key", "authentication_error")
		return
	}

	entry, ok := s.requestStore.Get(requestID)
	if !ok || entry.projectID != project.ID {
		http.NotFound(w, r)
		return
	}

	resp := map[string]any{
		"status":     entry.status,
		"activation": nil,
	}
	if entry.status == "completed" && entry.activation != nil {
		resp["activation"] = entry.activation
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
