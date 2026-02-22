package server

import (
	"testing"

	"github.com/straja-ai/straja-gateway/internal/strajaguard"
)

func TestSGFallbackNetworkUsesCache(t *testing.T) {
	allow, status, reason := sgFallbackDecision(true, strajaguard.ValidateNetworkError, "v1")
	if !allow {
		t.Fatalf("expected allowCache=true")
	}
	if status != "offline_cached_bundle" || reason != "network_error" {
		t.Fatalf("unexpected status/reason: %s/%s", status, reason)
	}
}

func TestSGFallbackInvalidTrustNoCache(t *testing.T) {
	allow, status, reason := sgFallbackDecision(true, strajaguard.ValidateInvalidTrust, "v1")
	if allow {
		t.Fatalf("expected allowCache=false")
	}
	if status != "disabled_invalid_trust_key" || reason != "invalid_trust_key" {
		t.Fatalf("unexpected status/reason: %s/%s", status, reason)
	}
}

func TestSGFallbackMissingTrustKeyNoCache(t *testing.T) {
	allow, status, reason := sgFallbackDecision(false, strajaguard.ValidateOtherError, "v1")
	if allow {
		t.Fatalf("expected allowCache=false")
	}
	if status != "disabled_missing_trust_key" || reason != "missing_trust_key" {
		t.Fatalf("unexpected status/reason: %s/%s", status, reason)
	}
}
