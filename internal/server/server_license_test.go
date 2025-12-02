package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/intel"
	"github.com/straja-ai/straja/internal/license"
	"github.com/straja-ai/straja/internal/policy"
)

func TestValidateLicenseOnline_OKStatusesKeepEnabled(t *testing.T) {
	cases := []string{"ok", "active"}
	for _, status := range cases {
		t.Run(status, func(t *testing.T) {
			s := &Server{
				cfg: &config.Config{
					Intelligence: config.IntelligenceConfig{
						LicenseServerURL: "https://example.test/validate",
					},
				},
				licenseKey:    "dummy",
				licenseClaims: &license.LicenseClaims{Tier: "other"},
				intelStatus:   "enabled",
				intelEnabled:  true,
				httpClient:    fakeHTTPClient(`{"status":"` + status + `","tier":"free","message":"Valid license"}`),
			}

			if err := s.ValidateLicenseOnline(context.Background()); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if s.intelStatus != "enabled" {
				t.Fatalf("expected intelStatus enabled, got %s", s.intelStatus)
			}
			if got := s.licenseClaims.Tier; got != "free" {
				t.Fatalf("expected tier updated to free, got %s", got)
			}
		})
	}
}

func TestValidateLicenseOnline_NonOKDisablesIntel(t *testing.T) {
	s := &Server{
		cfg: &config.Config{
			Intelligence: config.IntelligenceConfig{
				LicenseServerURL: "https://example.test/validate",
			},
			Policy: config.PolicyConfig{},
		},
		licenseKey:    "dummy",
		licenseClaims: &license.LicenseClaims{},
		intelStatus:   "enabled",
		intelEnabled:  true,
		policy:        policy.NewBasic(config.PolicyConfig{}, intel.NewNoop()),
		httpClient:    fakeHTTPClient(`{"status":"revoked","message":"Revoked"}`),
	}

	if err := s.ValidateLicenseOnline(context.Background()); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if s.intelEnabled {
		t.Fatalf("expected intelEnabled to be false after revoke")
	}
	if !strings.HasPrefix(s.intelStatus, "disabled_") {
		t.Fatalf("expected intelStatus disabled_, got %s", s.intelStatus)
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
