package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/straja-ai/straja/internal/auth"
	"github.com/straja-ai/straja/internal/config"
)

func newConsoleSessionServer(t *testing.T) *Server {
	cfg := newTestConfig(t)
	cfg.Providers = map[string]config.ProviderConfig{
		"upstream": {Type: "openai", BaseURL: "https://example.com", APIKey: "upstream-key"},
	}
	cfg.DefaultProvider = "upstream"
	cfg.Projects = []config.ProjectConfig{
		{ID: "demo", Provider: "upstream", APIKeys: []string{"test-key"}},
	}
	cfg.Console.Enabled = true
	cfg.Console.SessionSecret = "test-secret"
	cfg.Logging.ActivationLevel = "metadata"
	authz := auth.NewAuth(cfg)
	return New(cfg, authz, "")
}

func TestConsoleSessionCreation(t *testing.T) {
	srv := newConsoleSessionServer(t)
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)

	payload := map[string]any{"project_id": "demo"}
	body, _ := json.Marshal(payload)
	res, err := http.Post(ts.URL+"/console/api/session", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("session request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	if len(res.Cookies()) == 0 {
		t.Fatalf("expected session cookie")
	}
}

func TestV1ToolgateWithConsoleSession(t *testing.T) {
	srv := newConsoleSessionServer(t)
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	payload := map[string]any{"project_id": "demo"}
	body, _ := json.Marshal(payload)
	res, err := client.Post(ts.URL+"/console/api/session", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("session request failed: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	check := map[string]any{
		"tool_name": "shell.exec",
		"args":      map[string]any{"command": "echo ok"},
	}
	checkBody, _ := json.Marshal(check)
	resp, err := client.Post(ts.URL+"/v1/toolgate/check", "application/json", bytes.NewBuffer(checkBody))
	if err != nil {
		t.Fatalf("toolgate request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestV1AuthPrefersBearer(t *testing.T) {
	srv := newConsoleSessionServer(t)
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	payload := map[string]any{"project_id": "demo"}
	body, _ := json.Marshal(payload)
	res, err := client.Post(ts.URL+"/console/api/session", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("session request failed: %v", err)
	}
	res.Body.Close()

	check := map[string]any{"tool_name": "shell.exec", "args": map[string]any{"command": "echo ok"}}
	checkBody, _ := json.Marshal(check)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/toolgate/check", bytes.NewBuffer(checkBody))
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("toolgate request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestV1RequestsStatusWithConsoleSession(t *testing.T) {
	srv := newConsoleSessionServer(t)
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	payload := map[string]any{"project_id": "demo"}
	body, _ := json.Marshal(payload)
	res, err := client.Post(ts.URL+"/console/api/session", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("session request failed: %v", err)
	}
	res.Body.Close()

	check := map[string]any{
		"tool_name": "shell.exec",
		"args":      map[string]any{"command": "echo ok"},
	}
	checkBody, _ := json.Marshal(check)
	resp, err := client.Post(ts.URL+"/v1/toolgate/check", "application/json", bytes.NewBuffer(checkBody))
	if err != nil {
		t.Fatalf("toolgate request failed: %v", err)
	}
	var checkResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&checkResp); err != nil {
		t.Fatalf("decode toolgate response: %v", err)
	}
	resp.Body.Close()
	requestID, _ := checkResp["request_id"].(string)
	if requestID == "" {
		t.Fatalf("missing request_id")
	}

	statusResp, err := client.Get(ts.URL + "/v1/requests/" + requestID)
	if err != nil {
		t.Fatalf("status request failed: %v", err)
	}
	defer statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", statusResp.StatusCode)
	}
}
