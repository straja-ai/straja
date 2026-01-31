package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/straja-ai/straja/internal/auth"
	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/inference"
)

func newTestConfig(t *testing.T) *config.Config {
	t.Helper()

	cfg, err := config.Load("testdata/does-not-exist.yaml")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	cfg.Server.Addr = ":0"
	cfg.Server.MaxRequestBodyBytes = 64
	cfg.Server.MaxNonStreamResponseBytes = 1024 * 1024
	cfg.Server.MaxInFlightRequests = 5
	cfg.Server.UpstreamTimeout = 2 * time.Second
	cfg.Server.ReadHeaderTimeout = time.Second
	cfg.Server.ReadTimeout = time.Second
	cfg.Server.WriteTimeout = time.Second
	cfg.Server.IdleTimeout = time.Second

	cfg.Providers = map[string]config.ProviderConfig{}
	cfg.DefaultProvider = ""
	cfg.Projects = []config.ProjectConfig{
		{
			ID:       "p1",
			Provider: "echo",
			APIKeys:  []string{"test-key"},
		},
	}

	cfg.Logging.ActivationLevel = "metadata"
	cfg.Intelligence.Enabled = false
	cfg.Security.Enabled = false
	cfg.Intel.StrajaGuardV1.Enabled = false
	cfg.Intel.StrajaGuardV1.RequireML = false

	return cfg
}

func newTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()

	authz := auth.NewAuth(cfg)
	return New(cfg, authz, "")
}

func TestRequestBodyLimitReturns413(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Server.MaxRequestBodyBytes = 10

	srv := newTestServer(t, cfg)

	payload := `{"model":"gpt","messages":[{"role":"user","content":"` + strings.Repeat("a", 32) + `"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer test-key")

	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
}

type blockingProvider struct {
	started chan struct{}
	release chan struct{}
}

func (p *blockingProvider) ChatCompletion(ctx context.Context, req *inference.Request) (*inference.Response, error) {
	select {
	case p.started <- struct{}{}:
	default:
	}

	select {
	case <-p.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return &inference.Response{
		Message: inference.Message{
			Role:    "assistant",
			Content: "ok",
		},
	}, nil
}

func TestConcurrencyLimiterReturns429(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Server.MaxInFlightRequests = 1
	cfg.Server.MaxRequestBodyBytes = 1024

	srv := newTestServer(t, cfg)

	block := &blockingProvider{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	srv.providers["echo"] = block

	body := `{"model":"gpt","messages":[{"role":"user","content":"hi"}]}`
	req1 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req1.Header.Set("Authorization", "Bearer test-key")
	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req2.Header.Set("Authorization", "Bearer test-key")

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		rr := httptest.NewRecorder()
		srv.mux.ServeHTTP(rr, req1)
		if rr.Code != http.StatusOK {
			t.Errorf("first request status = %d", rr.Code)
		}
	}()

	select {
	case <-block.started:
	case <-time.After(2 * time.Second):
		t.Fatalf("first request did not reach provider")
	}

	rr2 := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr2.Code)
	}

	close(block.release)
	wg.Wait()
}

func TestHealthzOK(t *testing.T) {
	cfg := newTestConfig(t)
	srv := newTestServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestReadyzRequiresMLWhenConfigured(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Intel.StrajaGuardV1.RequireML = true

	srv := newTestServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}

func TestReadyzAllowsRegexOnlyWhenMLNotRequired(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Intel.StrajaGuardV1.RequireML = false

	srv := newTestServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}
