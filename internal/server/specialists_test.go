package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/straja-ai/straja/internal/auth"
	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/intel"
	"github.com/straja-ai/straja/internal/policy"
	"github.com/straja-ai/straja/internal/safety"
	"github.com/straja-ai/straja/internal/strajaguard"
	"go.opentelemetry.io/otel/trace"
)

type fakeSpecialistsEngine struct {
	result *strajaguard.SpecialistsResult
	err    error
}

func (f *fakeSpecialistsEngine) AnalyzeText(ctx context.Context, text string) (*strajaguard.SpecialistsResult, error) {
	return f.result, f.err
}

func newSpecialistsResponsesServer(t *testing.T, upstreamBaseURL string, fake *fakeSpecialistsEngine) *Server {
	t.Helper()

	cfg := newTestConfig(t)
	cfg.Providers = map[string]config.ProviderConfig{
		"upstream": {
			Type:    "openai",
			BaseURL: upstreamBaseURL,
			APIKey:  "upstream-key",
		},
	}
	cfg.DefaultProvider = "upstream"
	cfg.Projects = []config.ProjectConfig{
		{
			ID:       "p1",
			Provider: "upstream",
			APIKeys:  []string{"test-key"},
		},
	}
	cfg.Logging.ActivationLevel = "metadata"
	cfg.Server.MaxRequestBodyBytes = 1024 * 1024
	cfg.Security.Enabled = true
	cfg.Security.PII = config.PIICategoryConfig{
		RegexEnabled:    false,
		MLEnabled:       true,
		MLWarnThreshold: 0.5,
		ActionOnMLOnly:  "redact",
	}
	cfg.Intelligence.Enabled = false
	cfg.Intel.StrajaGuardV1.Enabled = false
	cfg.Intel.StrajaGuardV1.RequireML = false

	authz := auth.NewAuth(cfg)
	srv := New(cfg, authz)
	srv.policy = policy.NewBasic(cfg.Policy, cfg.Security, intel.NewNoop(), nil, fake, trace.NewNoopTracerProvider().Tracer("test"), cfg.StrajaGuard)
	srv.specialistsEngine = fake
	srv.strajaGuardStatus = "online_validated"
	srv.strajaGuardFamily = "strajaguard_v1_specialists"
	srv.activeBundleVer = "test"
	return srv
}

func TestResponsesNonStreamSpecialistsRedaction(t *testing.T) {
	email := "test@example.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":[{"content":[{"type":"output_text","text":"contact ` + email + `"}]}]}`))
	}))
	t.Cleanup(upstream.Close)

	fake := &fakeSpecialistsEngine{
		result: &strajaguard.SpecialistsResult{
			Scores: map[string]float32{
				"contains_personal_data": 1.0,
			},
			PIIEntities: []safety.PIIEntity{
				{EntityType: "EMAIL", StartByte: strings.Index("contact "+email, email), EndByte: strings.Index("contact "+email, email) + len(email), Source: "pii_ner"},
			},
		},
	}
	srv := newSpecialistsResponsesServer(t, upstream.URL+"/v1", fake)

	body := `{"model":"gpt-4.1-mini","input":"hello"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "[REDACTED_EMAIL]") {
		t.Fatalf("expected redacted output, got %s", rr.Body.String())
	}
}

func TestResponsesStreamingSpecialistsRedactionSuggested(t *testing.T) {
	email := "test@example.com"
	events := []string{
		`data: {"type":"response.output_text.delta","delta":"contact ` + email + `"}` + "\n\n",
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

	text := "contact " + email
	start := strings.Index(text, email)
	fake := &fakeSpecialistsEngine{
		result: &strajaguard.SpecialistsResult{
			Scores: map[string]float32{
				"contains_personal_data": 1.0,
			},
			PIIEntities: []safety.PIIEntity{
				{EntityType: "EMAIL", StartByte: start, EndByte: start + len(email), Source: "pii_ner"},
			},
		},
	}
	srv := newSpecialistsResponsesServer(t, upstream.URL+"/v1", fake)
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)

	body := `{"model":"gpt-4.1-mini","input":"hello","stream":true}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/responses", bytes.NewBufferString(body))
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
	bodyBytes, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(bodyBytes, []byte(email)) {
		t.Fatalf("expected streaming output unchanged, got %s", string(bodyBytes))
	}

	var act map[string]any
	for i := 0; i < 20; i++ {
		statusReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/straja/requests/"+reqID, nil)
		statusReq.Header.Set("Authorization", "Bearer test-key")
		statusResp, err := http.DefaultClient.Do(statusReq)
		if err != nil {
			t.Fatalf("status request: %v", err)
		}
		var body map[string]any
		if err := json.NewDecoder(statusResp.Body).Decode(&body); err == nil {
			if body["status"] == "completed" {
				act, _ = body["activation"].(map[string]any)
				statusResp.Body.Close()
				break
			}
		}
		statusResp.Body.Close()
		time.Sleep(50 * time.Millisecond)
	}
	if act == nil {
		t.Fatalf("expected activation payload")
	}
	summary := activationSummary(t, act)
	if summary["response_final"] != "allow" {
		t.Fatalf("expected summary.response_final allow, got %v", summary["response_final"])
	}
	if summary["response_note"] != "redaction_suggested" {
		t.Fatalf("expected summary.response_note redaction_suggested, got %v", summary["response_note"])
	}
}
