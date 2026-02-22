package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/straja-ai/straja-gateway/internal/consoleauth"
)

type consoleSessionRequest struct {
	ProjectID string `json:"project_id"`
}

type consoleSessionResponse struct {
	Status    string    `json:"status"`
	ProjectID string    `json:"project_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) handleConsoleSession(w http.ResponseWriter, r *http.Request) {
	setConsoleRobotsHeader(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.cfg.Console.Enabled {
		http.Error(w, "console sessions disabled", http.StatusForbidden)
		return
	}
	if strings.TrimSpace(s.cfg.Console.SessionSecret) == "" {
		http.Error(w, "console session secret not configured", http.StatusInternalServerError)
		return
	}

	var req consoleSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	projectID := strings.TrimSpace(req.ProjectID)
	if projectID == "" {
		http.Error(w, "missing project_id", http.StatusBadRequest)
		return
	}
	if _, ok := s.projectProviders[projectID]; !ok {
		http.Error(w, "unknown project_id", http.StatusBadRequest)
		return
	}

	token, exp, err := consoleauth.IssueConsoleSession(projectID, s.cfg.Console.SessionTTL, s.cfg.Console.SessionSecret)
	if err != nil {
		http.Error(w, "failed to issue session", http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:     s.cfg.Console.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  exp,
	}
	if isHTTPS(r) {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(consoleSessionResponse{
		Status:    "ok",
		ProjectID: projectID,
		ExpiresAt: exp,
	})
}

func (s *Server) handleConsoleLogout(w http.ResponseWriter, r *http.Request) {
	setConsoleRobotsHeader(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.cfg.Console.Enabled {
		http.Error(w, "console sessions disabled", http.StatusForbidden)
		return
	}
	cookie := &http.Cookie{
		Name:     s.cfg.Console.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	}
	if isHTTPS(r) {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
