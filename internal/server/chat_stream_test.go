package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/straja-ai/straja/internal/config"
)

func TestChatCompletionsStreamingPassthrough(t *testing.T) {
	events := []string{
		`data: {"id":"chatcmpl_1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"hello"}}]}` + "\n\n",
		"data: [DONE]\n\n",
	}
	upstreamSawStream := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		var reqBody map[string]any
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("decode upstream request: %v", err)
		}
		if v, ok := reqBody["stream"].(bool); ok && v {
			upstreamSawStream = true
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

	srv := newResponsesTestServer(t, upstream.URL+"/v1", nil)
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)

	body := `{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"hello"}],"stream":true}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if !upstreamSawStream {
		t.Fatalf("expected upstream chat request with stream=true")
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected Content-Type text/event-stream, got %q", ct)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	want := ""
	for _, e := range events {
		want += e
	}
	if string(got) != want {
		t.Fatalf("stream mismatch:\nwant=%q\ngot=%q", want, string(got))
	}
}

func TestChatCompletionsStreamingToolCallArgumentsRedactionSuggested(t *testing.T) {
	events := []string{
		`data: {"id":"chatcmpl_1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"run","arguments":"{\"command\":\"echo sk-test-abcdefghijklmnopqrstuv\"}"}}]}}]}` + "\n\n",
		"data: [DONE]\n\n",
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
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

	srv := newResponsesTestServer(t, upstream.URL+"/v1", func(cfg *config.Config) {
		cfg.Intelligence.Enabled = true
		cfg.Security.Enabled = false
		cfg.Policy.PII = "redact"
		cfg.Policy.PIIEntities = config.PIIEntitiesConfig{
			Email:      true,
			Phone:      true,
			CreditCard: true,
			IBAN:       true,
			Tokens:     true,
		}
	})
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)

	body := `{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"hello"}],"stream":true}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	reqID := resp.Header.Get("X-Straja-Request-Id")
	if reqID == "" {
		t.Fatalf("missing request id")
	}
	_, _ = io.ReadAll(resp.Body)

	var act map[string]any
	for i := 0; i < 20; i++ {
		statusReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/straja/requests/"+reqID, nil)
		statusReq.Header.Set("Authorization", "Bearer test-key")
		statusResp, err := http.DefaultClient.Do(statusReq)
		if err != nil {
			t.Fatalf("status request: %v", err)
		}
		var statusBody map[string]any
		if err := json.NewDecoder(statusResp.Body).Decode(&statusBody); err == nil && statusBody["status"] == "completed" {
			act, _ = statusBody["activation"].(map[string]any)
			statusResp.Body.Close()
			break
		}
		statusResp.Body.Close()
		time.Sleep(50 * time.Millisecond)
	}
	if act == nil {
		t.Fatalf("expected activation payload")
	}
	summary := activationSummary(t, act)
	if summary["response_final"] != "warn" {
		t.Fatalf("expected summary.response_final warn, got %v", summary["response_final"])
	}
	if summary["response_note"] != "redaction_suggested" {
		t.Fatalf("expected summary.response_note redaction_suggested, got %v", summary["response_note"])
	}
}
