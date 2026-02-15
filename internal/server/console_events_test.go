package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
)

func newConsoleClient(t *testing.T, baseURL string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}

	payload := map[string]any{"project_id": "demo"}
	body, _ := json.Marshal(payload)
	res, err := client.Post(baseURL+"/console/api/session", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("session request failed: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from session, got %d", res.StatusCode)
	}
	return client
}

func TestConsoleEventsFallbackFromRequestStore(t *testing.T) {
	srv := newConsoleSessionServer(t)
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)

	client := newConsoleClient(t, ts.URL)

	check := map[string]any{
		"tool_name": "shell.exec",
		"args":      map[string]any{"command": "echo ok"},
	}
	checkBody, _ := json.Marshal(check)
	resp, err := client.Post(ts.URL+"/v1/toolgate/check", "application/json", bytes.NewBuffer(checkBody))
	if err != nil {
		t.Fatalf("toolgate request failed: %v", err)
	}
	var checkResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&checkResp); err != nil {
		t.Fatalf("decode toolgate response: %v", err)
	}
	resp.Body.Close()
	requestID, _ := checkResp["request_id"].(string)
	if requestID == "" {
		t.Fatalf("missing request_id")
	}

	eventsResp, err := client.Get(ts.URL + "/console/api/events?limit=10&include_totals=1")
	if err != nil {
		t.Fatalf("events request failed: %v", err)
	}
	defer eventsResp.Body.Close()
	if eventsResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", eventsResp.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(eventsResp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode events payload: %v", err)
	}
	items, _ := payload["items"].([]any)
	if len(items) == 0 {
		t.Fatalf("expected at least one event item")
	}
	first, _ := items[0].(map[string]any)
	if first["request_id"] != requestID {
		t.Fatalf("expected first request_id %q, got %v", requestID, first["request_id"])
	}
	if totals, ok := payload["totals"].(map[string]any); !ok || int(totals["total"].(float64)) < 1 {
		t.Fatalf("expected totals.total >= 1, got %v", payload["totals"])
	}
}

func TestConsoleEventsFallbackIncludesPendingEntry(t *testing.T) {
	srv := newConsoleSessionServer(t)
	srv.requestStore.Start("pending-1", "demo")
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)

	client := newConsoleClient(t, ts.URL)
	eventsResp, err := client.Get(ts.URL + "/console/api/events?limit=10")
	if err != nil {
		t.Fatalf("events request failed: %v", err)
	}
	defer eventsResp.Body.Close()
	if eventsResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", eventsResp.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(eventsResp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode events payload: %v", err)
	}
	items, _ := payload["items"].([]any)
	if len(items) == 0 {
		t.Fatalf("expected pending event item")
	}
	first, _ := items[0].(map[string]any)
	reqFinal, _ := first["request_final"].(map[string]any)
	if reqFinal["action"] != "pending" {
		t.Fatalf("expected pending action, got %v", reqFinal["action"])
	}
}
