package activation

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFileSinkWritesJSONL(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "nested", "events.jsonl")

	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("file sink: %v", err)
	}

	ev1 := &Event{Version: "2", Timestamp: time.Now(), RequestID: "req-1", Meta: ActivationMeta{ProjectID: "p1", ProviderID: "prov", Provider: "prov", Mode: ModeNonStream}}
	ev2 := &Event{Version: "2", Timestamp: time.Now(), RequestID: "req-2", Meta: ActivationMeta{ProjectID: "p1", ProviderID: "prov", Provider: "prov", Mode: ModeNonStream}}

	if err := sink.Deliver(context.Background(), ev1); err != nil {
		t.Fatalf("deliver 1: %v", err)
	}
	if err := sink.Deliver(context.Background(), ev2); err != nil {
		t.Fatalf("deliver 2: %v", err)
	}
	if err := sink.Close(context.Background()); err != nil {
		t.Fatalf("close sink: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var decoded Event
	if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil {
		t.Fatalf("unmarshal jsonl line: %v", err)
	}
	if decoded.RequestID != "req-1" {
		t.Fatalf("expected request_id req-1, got %s", decoded.RequestID)
	}
}

func TestWebhookSinkHandlesNon2xx(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("fail"))
	}))

	sink, err := NewWebhookSink(srv.URL, map[string]string{"X-Test": "1"}, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("webhook sink: %v", err)
	}
	ev := &Event{Version: "2", Timestamp: time.Now(), RequestID: "req-1", Meta: ActivationMeta{Mode: ModeNonStream}}
	if err := sink.Deliver(context.Background(), ev); err == nil {
		t.Fatalf("expected non-2xx to return error")
	} else if !strings.Contains(err.Error(), "status") {
		t.Fatalf("error should mention status, got %v", err)
	}
}

func TestEmitterDropsWhenQueueFull(t *testing.T) {
	wait := make(chan struct{})
	sink := &blockingSink{wait: wait}
	em := NewEmitter(EmitterConfig{QueueSize: 1, Workers: 1, ShutdownTimeout: time.Second}, []Sink{sink})

	ev := &Event{Version: "2", Timestamp: time.Now(), RequestID: "r1", Meta: ActivationMeta{Mode: ModeNonStream}}
	em.Emit(context.Background(), ev)
	em.Emit(context.Background(), ev)
	em.Emit(context.Background(), ev)

	metrics := em.MetricsSnapshot()
	if metrics.Dropped() == 0 {
		t.Fatalf("expected dropped events when queue is full")
	}

	close(wait)
	em.Close(context.Background())
}

func TestEmitterWebhookIntegration(t *testing.T) {
	var (
		mu        sync.Mutex
		received  []Event
		requestCT int
	)
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		requestCT++
		var ev Event
		if err := json.NewDecoder(r.Body).Decode(&ev); err == nil {
			mu.Lock()
			received = append(received, ev)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))

	sink, err := NewWebhookSink(srv.URL, nil, time.Second)
	if err != nil {
		t.Fatalf("webhook sink: %v", err)
	}
	em := NewEmitter(EmitterConfig{QueueSize: 8, Workers: 1, ShutdownTimeout: time.Second}, []Sink{sink})
	defer em.Close(context.Background())

	ev := &Event{Version: "2", Timestamp: time.Now(), RequestID: "integration", Meta: ActivationMeta{ProjectID: "p", ProviderID: "prov", Provider: "prov", Mode: ModeNonStream}}
	for i := 0; i < 5; i++ {
		em.Emit(context.Background(), ev)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		if len(received) >= 5 {
			mu.Unlock()
			break
		}
		mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for webhook events, got %d", len(received))
		}
		time.Sleep(20 * time.Millisecond)
	}

	metrics := em.MetricsSnapshot()
	if metrics.SinkSuccess(sink.Name()) == 0 {
		t.Fatalf("expected sink success counter to increase")
	}
	if metrics.Dropped() != 0 {
		t.Fatalf("did not expect dropped events, got %d", metrics.Dropped())
	}
}

type blockingSink struct {
	wait chan struct{}
}

func (s *blockingSink) Name() string { return "blocking" }

func (s *blockingSink) Deliver(context.Context, *Event) error {
	<-s.wait
	return nil
}

func (s *blockingSink) Close(context.Context) error {
	if s.wait != nil {
		select {
		case <-s.wait:
		default:
			close(s.wait)
		}
	}
	return nil
}

func newTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping: cannot open listener: %v", err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}
