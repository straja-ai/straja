package strajaguard

import "testing"

func TestDecideFallbackKeepsCurrentOnFailure(t *testing.T) {
	current, mode, err := DecideFallback("v1", true, false, assertError("boom"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if current != "v1" || mode != "ml" {
		t.Fatalf("expected to keep current ml bundle, got version=%s mode=%s", current, mode)
	}
}

func TestDecideFallbackRegexOnlyWhenAllowed(t *testing.T) {
	current, mode, err := DecideFallback("", false, true, assertError("fail"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if current != "" || mode != "regex_only" {
		t.Fatalf("expected regex_only fallback, got version=%s mode=%s", current, mode)
	}
}

func TestDecideFallbackRequireMLFails(t *testing.T) {
	_, _, err := DecideFallback("", true, false, assertError("fail"))
	if err == nil {
		t.Fatalf("expected error when require_ml and no bundle")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func assertError(msg string) error { return errString(msg) }
