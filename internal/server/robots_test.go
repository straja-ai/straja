package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleRobots(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rr := httptest.NewRecorder()

	handleRobots(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/plain" {
		t.Fatalf("expected Content-Type text/plain, got %q", ct)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("expected Cache-Control no-store, got %q", cc)
	}
	if got := rr.Body.String(); got != robotsTxt {
		t.Fatalf("unexpected body, got %q", got)
	}
}
