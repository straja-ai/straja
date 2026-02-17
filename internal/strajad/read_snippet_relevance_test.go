package strajad

import (
	"net/http"
	"strings"
	"testing"
)

func TestReadSnippets_PrefersRelevantSpanOverPDFNoise(t *testing.T) {
	d := newTestDaemon(t)
	mustUnlock(t, d, "relevance-pass", "")

	content := strings.Join([]string{
		"4215 0 R (M3 9 72634 21.) 4216 0 R (M3 9 74074 15 4 When the vehicle speed is between approximately 25 MPH and 90 MPH.)",
		"Lane Departure Prevention Function details are listed below.",
		"EyeSight is Subaru's driver assist technology that uses stereo cameras to support safer driving.",
	}, " ")

	writeReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      "write-relevance",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "vault.write",
			"arguments": map[string]any{
				"collection": "work",
				"title":      "Subaru eyesight manual.pdf",
				"content":    content,
			},
		},
	}
	rr := performMCP(t, d, writeReq, "127.0.0.1:3456", "test-token")
	if rr.Code != http.StatusOK {
		t.Fatalf("write relevance doc failed status=%d body=%s", rr.Code, rr.Body.String())
	}
	id := mustObject(t, mustObject(t, mustPayload(t, rr.Body.Bytes()), "result"), "data")["id"].(string)

	readReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      "read-relevance",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "vault.read_snippets",
			"arguments": map[string]any{
				"ids":                   []string{id},
				"query":                 "what is eyesight?",
				"max_bytes":             2048,
				"max_chars_per_snippet": 280,
			},
		},
	}
	rr = performMCP(t, d, readReq, "127.0.0.1:3456", "test-token")
	if rr.Code != http.StatusOK {
		t.Fatalf("read relevance snippet failed status=%d body=%s", rr.Code, rr.Body.String())
	}

	data := mustObject(t, mustObject(t, mustPayload(t, rr.Body.Bytes()), "result"), "data")
	snippets, ok := data["snippets"].([]any)
	if !ok || len(snippets) == 0 {
		t.Fatalf("expected at least one snippet, got %v", data["snippets"])
	}
	first := mustAnyObject(t, snippets[0])
	snippet, _ := first["snippet"].(string)
	snippetLower := strings.ToLower(snippet)
	if !strings.Contains(snippetLower, "eyesight is subaru") {
		t.Fatalf("expected relevance snippet to include eyesight definition, got %q", snippet)
	}
	if strings.Contains(snippet, "0 R") {
		t.Fatalf("expected noisy PDF object references to be removed, got %q", snippet)
	}
}
