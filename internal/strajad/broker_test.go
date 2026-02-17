package strajad

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInstallBrokerModel_PullsConfiguredModel(t *testing.T) {
	var gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode pull body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BrokerProvider = "ollama"
	cfg.BrokerEndpoint = srv.URL
	cfg.BrokerModel = "phi4-mini:3.8b"
	cfg.BrokerTimeout = 2 * time.Second

	if err := InstallBrokerModel(context.Background(), cfg); err != nil {
		t.Fatalf("install broker model failed: %v", err)
	}
	if gotPath != "/api/pull" {
		t.Fatalf("expected pull endpoint /api/pull, got %q", gotPath)
	}
	if model, _ := gotBody["model"].(string); model != cfg.BrokerModel {
		t.Fatalf("expected model %q, got %q", cfg.BrokerModel, model)
	}
	stream, _ := gotBody["stream"].(bool)
	if stream {
		t.Fatalf("expected stream=false for model pull")
	}
}

func TestOllamaBrokerPlan_ParsesStructuredJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Fatalf("expected /api/generate, got %q", r.URL.Path)
		}
		defer r.Body.Close()
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode generate body: %v", err)
		}
		if model, _ := req["model"].(string); model != "phi4-mini:3.8b" {
			t.Fatalf("expected model in request, got %q", model)
		}
		if format, _ := req["format"].(string); format != "json" {
			t.Fatalf("expected format=json, got %q", format)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"response":"{\"plan\":[\"search\",\"read\"],\"recommended_tool_calls\":[{\"name\":\"vault.search\",\"args\":{\"query\":\"roadmap\",\"limit\":3}}],\"approvals_needed\":[\"none\"],\"safety_notes\":[\"bounded\"]}"
		}`))
	}))
	defer srv.Close()

	broker, err := newOllamaBroker(srv.URL, "phi4-mini:3.8b", 2*time.Second, srv.Client())
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	in := plannerInput{
		Task:              "Summarize roadmap",
		Collection:        "work",
		MaxTaskChars:      4000,
		MaxSearchResults:  10,
		MaxSnippetObjects: 5,
		MaxSnippetBytes:   4096,
		MaxSnippetChars:   512,
		MaxWriteChars:     4000,
		MaxIngestBytes:    256 * 1024,
	}
	fallback := buildDeterministicPlan(in)
	draft, err := broker.Plan(context.Background(), in, fallback)
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if len(draft.Plan) != 2 {
		t.Fatalf("expected 2 plan steps, got %d", len(draft.Plan))
	}
	if len(draft.RecommendedToolCalls) != 1 {
		t.Fatalf("expected one recommended call, got %d", len(draft.RecommendedToolCalls))
	}
	if draft.RecommendedToolCalls[0].Name != "vault.search" {
		t.Fatalf("expected vault.search recommendation, got %q", draft.RecommendedToolCalls[0].Name)
	}
}

func TestDecodeBrokerPlanDraft_StripsCodeFence(t *testing.T) {
	raw := "```json\n{\"plan\":[\"step\"],\"recommended_tool_calls\":[],\"approvals_needed\":[],\"safety_notes\":[]}\n```"
	draft, err := decodeBrokerPlanDraft(raw)
	if err != nil {
		t.Fatalf("decode fenced response failed: %v", err)
	}
	if len(draft.Plan) != 1 || strings.TrimSpace(draft.Plan[0]) != "step" {
		t.Fatalf("unexpected plan payload: %#v", draft.Plan)
	}
}

func TestBrokerModelAvailable_ChecksTagsEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Fatalf("expected /api/tags, got %q", r.URL.Path)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"models": []map[string]any{
				{
					"name":  "phi4-mini:3.8b",
					"model": "phi4-mini:3.8b",
				},
			},
		})
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BrokerProvider = "ollama"
	cfg.BrokerEndpoint = srv.URL
	cfg.BrokerModel = "phi4-mini:3.8b"
	cfg.BrokerTimeout = 2 * time.Second

	present, err := BrokerModelAvailable(context.Background(), cfg)
	if err != nil {
		t.Fatalf("broker model available check failed: %v", err)
	}
	if !present {
		t.Fatalf("expected model to be reported present")
	}
}

func TestBrokerModelAvailable_ReturnsFalseWhenMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"models": []map[string]any{
				{
					"name":  "other-model:latest",
					"model": "other-model:latest",
				},
			},
		})
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BrokerProvider = "ollama"
	cfg.BrokerEndpoint = srv.URL
	cfg.BrokerModel = "phi4-mini:3.8b"
	cfg.BrokerTimeout = 2 * time.Second

	present, err := BrokerModelAvailable(context.Background(), cfg)
	if err != nil {
		t.Fatalf("broker model available check failed: %v", err)
	}
	if present {
		t.Fatalf("expected model to be reported missing")
	}
}
