package telemetry

import (
	"testing"
)

func TestSafeAttributesFiltersSecrets(t *testing.T) {
	kvs := map[string]interface{}{
		"prompt":        "should drop",
		"content":       "drop",
		"api_key":       "sk-123",
		"token":         "abc",
		"safe_key":      "ok",
		"long_string":   string(make([]byte, 600)),
		"short_string":  "fine",
		"project_id":    "proj",
		"authorization": "secret",
	}

	attrs := SafeAttributes(kvs)
	for _, a := range attrs {
		if a.Key == "prompt" || a.Key == "content" || a.Key == "api_key" || a.Key == "authorization" || a.Key == "token" {
			t.Fatalf("unexpected unsafe attribute %s", a.Key)
		}
		if a.Key == "long_string" {
			t.Fatalf("expected long string to be skipped")
		}
	}
}
