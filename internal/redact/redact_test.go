package redact

import (
	"strings"
	"testing"
)

func TestStringRedaction(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		disallow []string
		require  []string
	}{
		{
			name:     "bearer header",
			input:    "Authorization: Bearer sk-secret-123",
			disallow: []string{"sk-secret-123"},
			require:  []string{"[REDACTED]"},
		},
		{
			name:     "api keys slice",
			input:    "api_keys=[proj-key-1 proj-key-2]",
			disallow: []string{"proj-key-1", "proj-key-2"},
			require:  []string{"api_keys=[REDACTED]"},
		},
		{
			name:     "license key",
			input:    "license_key=STRAJA-PAID-1234-5678",
			disallow: []string{"STRAJA-PAID-1234-5678"},
			require:  []string{"license_key=[REDACTED]"},
		},
		{
			name:     "bundle url",
			input:    "manifest_url=https://example.com/bundles/manifest.json?sig=abc123",
			disallow: []string{"manifest.json?sig=abc123"},
			require:  []string{"https://example.com/manifest.json"},
		},
		{
			name:     "mixed token",
			input:    "Bearer abc key=supersecret token=anotherone STRAJA-FREE-AAAA file_base_url=https://lic.example.test/files/base/",
			disallow: []string{"abc", "supersecret", "anotherone", "STRAJA-FREE-AAAA", "files/base/"},
			require:  []string{"[REDACTED]", "https://lic.example.test/[REDACTED_PATH]"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := String(tc.input)
			for _, bad := range tc.disallow {
				if bad != "" && contains(out, bad) {
					t.Fatalf("output still contains %q: %s", bad, out)
				}
			}
			for _, want := range tc.require {
				if want == "" {
					continue
				}
				if !contains(out, want) {
					t.Fatalf("output missing required substring %q: %s", want, out)
				}
			}
		})
	}
}

func contains(s, sub string) bool {
	return s != "" && sub != "" && strings.Contains(s, sub)
}
