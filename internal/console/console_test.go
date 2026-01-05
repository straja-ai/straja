package console

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerSetsRobotsHeaderOnIndex(t *testing.T) {
	handler := Handler()
	req := httptest.NewRequest(http.MethodGet, "/console", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get(RobotsTagHeader); got != RobotsTagValue {
		t.Fatalf("expected %s header %q, got %q", RobotsTagHeader, RobotsTagValue, got)
	}
}

func TestHandlerSetsRobotsHeaderOnStatic(t *testing.T) {
	handler := Handler()
	req := httptest.NewRequest(http.MethodGet, "/console/static/console.html", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get(RobotsTagHeader); got != RobotsTagValue {
		t.Fatalf("expected %s header %q for static, got %q", RobotsTagHeader, RobotsTagValue, got)
	}
}
