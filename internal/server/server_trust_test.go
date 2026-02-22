package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/straja-ai/straja-gateway/internal/config"
	"github.com/straja-ai/straja-gateway/internal/intel"
	"github.com/straja-ai/straja-gateway/internal/policy"
	"github.com/straja-ai/straja-gateway/internal/trust"
	"go.opentelemetry.io/otel/trace"
)

func TestValidateTrustOnline_OKStatusesKeepEnabled(t *testing.T) {
	cases := []string{"ok", "active"}
	for _, status := range cases {
		t.Run(status, func(t *testing.T) {
			s := &Server{
				cfg: &config.Config{
					Intelligence: config.IntelligenceConfig{
						TrustServerURL: "https://example.test/validate",
					},
				},
				trustKey:     "dummy",
				trustClaims:  &trust.TrustClaims{Tier: "other"},
				intelStatus:  "enabled",
				intelEnabled: true,
				httpClient:   fakeHTTPClient(`{"status":"` + status + `","tier":"free","message":"Valid trust"}`),
			}

			if err := s.ValidateTrustOnline(context.Background()); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if s.intelStatus != "enabled" {
				t.Fatalf("expected intelStatus enabled, got %s", s.intelStatus)
			}
			if got := s.trustClaims.Tier; got != "free" {
				t.Fatalf("expected tier updated to free, got %s", got)
			}
		})
	}
}

func TestValidateTrustOnline_NonOKDisablesIntel(t *testing.T) {
	s := &Server{
		cfg: &config.Config{
			Intelligence: config.IntelligenceConfig{
				TrustServerURL: "https://example.test/validate",
			},
			Policy: config.PolicyConfig{},
		},
		trustKey:     "dummy",
		trustClaims:  &trust.TrustClaims{},
		intelStatus:  "enabled",
		intelEnabled: true,
		policy:       policy.NewBasic(config.PolicyConfig{}, config.SecurityConfig{}, intel.NewNoop(), nil, nil, trace.NewNoopTracerProvider().Tracer("test"), config.StrajaGuardConfig{}),
		httpClient:   fakeHTTPClient(`{"status":"revoked","message":"Revoked"}`),
	}

	if err := s.ValidateTrustOnline(context.Background()); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if s.intelEnabled {
		t.Fatalf("expected intelEnabled to be false after revoke")
	}
	if s.intelStatus != "regex_only_invalid_trust_key" {
		t.Fatalf("expected regex_only_invalid_trust_key, got %s", s.intelStatus)
	}
}

// fakeHTTPClient returns a client that always responds with the provided JSON body.
func fakeHTTPClient(body string) *http.Client {
	return &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(body)),
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		}),
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
