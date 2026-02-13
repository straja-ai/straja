package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/straja-ai/straja/internal/auth"
	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/strajaguard"
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

type fakeHealthySpecialistsEngine struct{}

func (f *fakeHealthySpecialistsEngine) AnalyzeText(ctx context.Context, text string) (*strajaguard.SpecialistsResult, error) {
	return &strajaguard.SpecialistsResult{}, nil
}

func (f *fakeHealthySpecialistsEngine) HealthCheck() error { return nil }

type fakeUnhealthySpecialistsEngine struct{}

func (f *fakeUnhealthySpecialistsEngine) AnalyzeText(ctx context.Context, text string) (*strajaguard.SpecialistsResult, error) {
	return &strajaguard.SpecialistsResult{}, nil
}

func (f *fakeUnhealthySpecialistsEngine) HealthCheck() error { return errors.New("assets missing") }

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

func TestReadyzRequireMLFailsForUnhealthySpecialists(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Intel.StrajaGuardV1.RequireML = true

	srv := newTestServer(t, cfg)
	srv.specialistsEngine = &fakeUnhealthySpecialistsEngine{}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	srv.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}

func TestReadinessModeRegexOnlyForUnhealthySpecialists(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Intel.StrajaGuardV1.RequireML = false

	srv := newTestServer(t, cfg)
	srv.specialistsEngine = &fakeUnhealthySpecialistsEngine{}

	resp, ready := srv.readiness()
	if !ready {
		t.Fatalf("expected ready=true when ML is optional")
	}
	if resp.Mode != "regex_only" {
		t.Fatalf("expected regex_only mode, got %s", resp.Mode)
	}
}

func TestStrajaGuardEnabledUsesSpecialistsHealth(t *testing.T) {
	srv := &Server{specialistsEngine: &fakeHealthySpecialistsEngine{}}
	if !srv.strajaGuardEnabled() {
		t.Fatalf("expected healthy specialists to count as enabled")
	}
	srv.specialistsEngine = &fakeUnhealthySpecialistsEngine{}
	if srv.strajaGuardEnabled() {
		t.Fatalf("expected unhealthy specialists to be treated as disabled")
	}
}

func TestNewKeepsExplicitBundleDir(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Security.Enabled = false
	cfg.Intel.StrajaGuardV1.Enabled = false
	cfg.Intel.StrajaGuard.Family = "strajaguard_v1_specialists"
	cfg.Intel.StrajaGuardV1.IntelDir = "/tmp/intel-root"
	cfg.Security.BundleDir = "/tmp/custom-bundle"

	_ = newTestServer(t, cfg)

	if cfg.Security.BundleDir != "/tmp/custom-bundle" {
		t.Fatalf("expected explicit bundle dir to be preserved, got %q", cfg.Security.BundleDir)
	}
}

func TestNewResolvesRelativeBundleDirFromConfigPath(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Security.Enabled = false
	cfg.Intel.StrajaGuardV1.Enabled = false
	cfg.Security.BundleDir = "./intel/strajaguard_v1_specialists"
	cfg.StrajaGuard.Specialists.ConfigPath = "./configs/strajaguard_specialists.yaml"

	root := t.TempDir()
	configPath := filepath.Join(root, "etc", "straja", "straja.yaml")

	authz := auth.NewAuth(cfg)
	_ = New(cfg, authz, configPath)

	wantBundleDir := filepath.Join(root, "etc", "straja", "intel", "strajaguard_v1_specialists")
	if cfg.Security.BundleDir != wantBundleDir {
		t.Fatalf("expected bundle dir %q, got %q", wantBundleDir, cfg.Security.BundleDir)
	}
	wantSpecialistsPath := filepath.Join(root, "etc", "straja", "configs", "strajaguard_specialists.yaml")
	if cfg.StrajaGuard.Specialists.ConfigPath != wantSpecialistsPath {
		t.Fatalf("expected specialists config path %q, got %q", wantSpecialistsPath, cfg.StrajaGuard.Specialists.ConfigPath)
	}
}
