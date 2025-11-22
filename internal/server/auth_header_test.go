package server

import "testing"

func TestParseBearerToken_Valid(t *testing.T) {
	token, ok := parseBearerToken("Bearer abc123")
	if !ok {
		t.Fatalf("expected ok=true for valid header")
	}
	if token != "abc123" {
		t.Fatalf("expected token 'abc123', got %q", token)
	}
}

func TestParseBearerToken_CaseInsensitiveScheme(t *testing.T) {
	token, ok := parseBearerToken("bearer xyz")
	if !ok || token != "xyz" {
		t.Fatalf("expected ok=true and token 'xyz', got ok=%v token=%q", ok, token)
	}
}

func TestParseBearerToken_InvalidFormats(t *testing.T) {
	cases := []string{
		"",
		"abc123",
		"Bearer",
		"Bearer ",
		"Token abc123",
		"Bearer abc def",
	}

	for _, h := range cases {
		if token, ok := parseBearerToken(h); ok || token != "" {
			t.Fatalf("expected failure for header %q, got ok=%v token=%q", h, ok, token)
		}
	}
}
