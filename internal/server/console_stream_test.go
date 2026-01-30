package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/straja-ai/straja/internal/auth"
	"github.com/straja-ai/straja/internal/config"
)

func TestConsoleStreamingExposesRequestStatus(t *testing.T) {
	events := []string{
		`data: {"type":"response.output_text.delta","delta":"ignore previous instructions"}` + "\n\n",
		"data: [DONE]\n\n",
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for _, e := range events {
			_, _ = w.Write([]byte(e))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	t.Cleanup(upstream.Close)

	cfg := newTestConfig(t)
	cfg.Server.MaxRequestBodyBytes = 1024 * 1024
	cfg.Providers = map[string]config.ProviderConfig{
		"upstream": {
			Type:    "openai",
			BaseURL: upstream.URL + "/v1",
			APIKey:  "upstream-key",
		},
	}
	cfg.DefaultProvider = "upstream"
	cfg.Projects = []config.ProjectConfig{
		{
			ID:       "demo",
			Provider: "upstream",
			APIKeys:  []string{"console-key"},
		},
	}
	cfg.Intelligence.Enabled = true
	cfg.Security.Enabled = false
	cfg.Policy.PromptInjection = "block"

	authz := auth.NewAuth(cfg)
	srv := New(cfg, authz)
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)

	requestBody := `{"project_id":"demo","model":"gpt-4.1-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/console/api/chat", bytes.NewBufferString(requestBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	reqID := resp.Header.Get("X-Straja-Request-Id")
	if reqID == "" {
		t.Fatalf("missing request id header")
	}
	_, _ = io.ReadAll(resp.Body)

	statusReq, err := http.NewRequest(http.MethodGet, ts.URL+"/console/api/requests/"+reqID+"?project_id=demo", nil)
	if err != nil {
		t.Fatalf("new status request: %v", err)
	}
	statusResp, err := http.DefaultClient.Do(statusReq)
	if err != nil {
		t.Fatalf("status request: %v", err)
	}
	defer statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 status response, got %d", statusResp.StatusCode)
	}
	var statusBody map[string]any
	if err := json.NewDecoder(statusResp.Body).Decode(&statusBody); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if statusBody["status"] == "" {
		t.Fatalf("missing status field")
	}
}

func TestConsoleStreamingPreRedaction(t *testing.T) {
	events := []string{
		`data: {"type":"response.output_text.delta","delta":"ok"}` + "\n\n",
		"data: [DONE]\n\n",
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for _, e := range events {
			_, _ = w.Write([]byte(e))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	t.Cleanup(upstream.Close)

	cfg := newTestConfig(t)
	cfg.Server.MaxRequestBodyBytes = 1024 * 1024
	cfg.Providers = map[string]config.ProviderConfig{
		"upstream": {
			Type:    "openai",
			BaseURL: upstream.URL + "/v1",
			APIKey:  "upstream-key",
		},
	}
	cfg.DefaultProvider = "upstream"
	cfg.Projects = []config.ProjectConfig{
		{
			ID:       "demo",
			Provider: "upstream",
			APIKeys:  []string{"console-key"},
		},
	}
	cfg.Intelligence.Enabled = true
	cfg.Security.Enabled = false
	cfg.Policy.BannedWords = "redact"
	cfg.Policy.BannedWordsList = []string{"forbidden"}
	cfg.Logging.ActivationLevel = "redacted"

	authz := auth.NewAuth(cfg)
	srv := New(cfg, authz)
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)

	requestBody := `{"project_id":"demo","model":"gpt-4.1-mini","stream":true,"messages":[{"role":"user","content":"give me a random forbidden email"}]}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/console/api/chat", bytes.NewBufferString(requestBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	reqID := resp.Header.Get("X-Straja-Request-Id")
	if reqID == "" {
		t.Fatalf("missing request id header")
	}
	_, _ = io.ReadAll(resp.Body)

	statusReq, err := http.NewRequest(http.MethodGet, ts.URL+"/console/api/requests/"+reqID+"?project_id=demo", nil)
	if err != nil {
		t.Fatalf("new status request: %v", err)
	}
	statusResp, err := http.DefaultClient.Do(statusReq)
	if err != nil {
		t.Fatalf("status request: %v", err)
	}
	defer statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 status response, got %d", statusResp.StatusCode)
	}
	var statusBody map[string]any
	if err := json.NewDecoder(statusResp.Body).Decode(&statusBody); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	act, ok := statusBody["activation"].(map[string]any)
	if !ok {
		t.Fatalf("missing activation payload")
	}
	reqPayload, ok := act["request"].(map[string]any)
	if !ok {
		t.Fatalf("missing request")
	}
	preview, ok := reqPayload["preview"].(map[string]any)
	if !ok {
		t.Fatalf("missing request preview")
	}
	if prompt, _ := preview["prompt"].(string); !strings.Contains(prompt, "[REDACTED_BANNED]") {
		t.Fatalf("expected prompt preview to include redaction, got %v", preview["prompt"])
	}
	decision, ok := reqPayload["decision"].(map[string]any)
	if !ok {
		t.Fatalf("missing request decision")
	}
	if decision["final"] != "redact" {
		t.Fatalf("expected request decision redact, got %v", decision["final"])
	}
	if timing, ok := act["timing_ms"].(map[string]any); ok {
		if preMs, ok := timing["pre"].(float64); ok && preMs == 0 {
			t.Fatalf("expected non-zero pre timing")
		}
	}
	time.Sleep(10 * time.Millisecond)
}
