package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/straja-ai/straja/internal/auth"
	"github.com/straja-ai/straja/internal/config"
)

func newToolgateTestServer(t *testing.T, mutate func(*config.Config)) *Server {
	t.Helper()

	cfg := newTestConfig(t)
	cfg.Providers = map[string]config.ProviderConfig{
		"upstream": {Type: "openai", BaseURL: "https://example.com", APIKey: "upstream-key"},
	}
	cfg.DefaultProvider = "upstream"
	cfg.Projects = []config.ProjectConfig{
		{ID: "demo", Provider: "upstream", APIKeys: []string{"test-key"}},
	}
	cfg.Logging.ActivationLevel = "metadata"
	cfg.Server.MaxRequestBodyBytes = 1024 * 1024
	if mutate != nil {
		mutate(cfg)
	}
	authz := auth.NewAuth(cfg)
	return New(cfg, authz, "")
}

func TestToolgateCheckAllow(t *testing.T) {
	srv := newToolgateTestServer(t, nil)
	payload := map[string]any{
		"tool_name": "shell.exec",
		"args":      map[string]any{"command": "echo hello"},
		"context":   map[string]any{"project_id": "demo"},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/toolgate/check", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if resp["decision"] != "allow" {
		t.Fatalf("expected decision allow, got %v", resp["decision"])
	}
	if resp["request_id"] == "" {
		t.Fatalf("missing request_id")
	}
	norm, _ := resp["normalized"].(map[string]any)
	if norm == nil || norm["available"] != true {
		t.Fatalf("expected normalized available true")
	}
}

func TestToolgateCheckBlockRmRf(t *testing.T) {
	srv := newToolgateTestServer(t, nil)
	payload := map[string]any{
		"tool_name": "shell.exec",
		"args":      map[string]any{"command": "rm -rf /"},
		"context":   map[string]any{"project_id": "demo"},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/toolgate/check", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	errObj, _ := resp["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("missing error object")
	}
	if errObj["code"] != "tool_blocked" {
		t.Fatalf("expected code tool_blocked, got %v", errObj["code"])
	}
	if errObj["rule_id"] != "rm_rf_root" {
		t.Fatalf("expected rule_id rm_rf_root, got %v", errObj["rule_id"])
	}
}

func TestToolgateCheckBlockSensitiveRead(t *testing.T) {
	srv := newToolgateTestServer(t, nil)
	payload := map[string]any{
		"tool_name": "filesystem.read",
		"args":      map[string]any{"path": "/home/test/.ssh/id_rsa"},
		"context":   map[string]any{"project_id": "demo"},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/toolgate/check", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	errObj, _ := resp["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("missing error object")
	}
	if errObj["rule_id"] != "read_sensitive_files" {
		t.Fatalf("expected rule_id read_sensitive_files, got %v", errObj["rule_id"])
	}
}

func TestToolgateCheckPrivilegeEscalationMode(t *testing.T) {
	srv := newToolgateTestServer(t, nil)

	payload := map[string]any{
		"tool_name": "shell.exec",
		"args":      map[string]any{"command": "sudo ls"},
		"context":   map[string]any{"project_id": "demo", "mode": "all_tools"},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/toolgate/check", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if resp["decision"] != "warn" {
		t.Fatalf("expected decision warn, got %v", resp["decision"])
	}

	payload = map[string]any{
		"tool_name": "shell.exec",
		"args":      map[string]any{"command": "sudo ls"},
		"context":   map[string]any{"project_id": "demo", "mode": "elevated_only"},
	}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/v1/toolgate/check", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")

	rr = httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestToolgateStatusEndpoint(t *testing.T) {
	srv := newToolgateTestServer(t, nil)
	payload := map[string]any{
		"tool_name": "shell.exec",
		"args":      map[string]any{"command": "echo ok"},
		"context":   map[string]any{"project_id": "demo"},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/toolgate/check", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	requestID, _ := resp["request_id"].(string)
	if requestID == "" {
		t.Fatalf("missing request_id")
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/v1/straja/requests/"+requestID, nil)
	statusReq.Header.Set("Authorization", "Bearer test-key")
	statusRR := httptest.NewRecorder()
	srv.mux.ServeHTTP(statusRR, statusReq)
	if statusRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", statusRR.Code)
	}
	var status map[string]any
	if err := json.Unmarshal(statusRR.Body.Bytes(), &status); err != nil {
		t.Fatalf("invalid status JSON: %v", err)
	}
	if status["status"] != "completed" {
		t.Fatalf("expected completed status, got %v", status["status"])
	}
	act, _ := status["activation"].(map[string]any)
	if act == nil {
		t.Fatalf("missing activation")
	}
	if act["request_id"] != requestID {
		t.Fatalf("expected activation request_id %s, got %v", requestID, act["request_id"])
	}
	summary, _ := act["summary"].(map[string]any)
	if summary == nil {
		t.Fatalf("missing summary")
	}
	if summary["request_final"] != "allow" {
		t.Fatalf("expected request_final allow, got %v", summary["request_final"])
	}
	if summary["response_final"] != "n/a" {
		t.Fatalf("expected response_final n/a, got %v", summary["response_final"])
	}
}
