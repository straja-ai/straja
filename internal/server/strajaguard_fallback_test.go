package server

import (
	"testing"

	"github.com/straja-ai/straja/internal/strajaguard"
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

func TestSGFallbackInvalidLicenseNoCache(t *testing.T) {
	allow, status, reason := sgFallbackDecision(true, strajaguard.ValidateInvalidLicense, "v1")
	if allow {
		t.Fatalf("expected allowCache=false")
	}
	if status != "disabled_invalid_license" || reason != "invalid_license" {
		t.Fatalf("unexpected status/reason: %s/%s", status, reason)
	}
}

func TestSGFallbackMissingLicenseNoCache(t *testing.T) {
	allow, status, reason := sgFallbackDecision(false, strajaguard.ValidateOtherError, "v1")
	if allow {
		t.Fatalf("expected allowCache=false")
	}
	if status != "disabled_missing_license" || reason != "missing_license" {
		t.Fatalf("unexpected status/reason: %s/%s", status, reason)
	}
}
