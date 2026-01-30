package server

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (s *Server) handleConsoleRequestStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	setConsoleRobotsHeader(w)

	requestID := strings.TrimPrefix(r.URL.Path, "/console/api/requests/")
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		http.NotFound(w, r)
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		http.Error(w, "missing project_id", http.StatusBadRequest)
		return
	}

	entry, ok := s.requestStore.Get(requestID)
	if !ok || entry.projectID != projectID {
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
