package activation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/straja-ai/straja-gateway/internal/config"
)

func TestTelegramSinkSendsOnBlock(t *testing.T) {
	t.Setenv("TG_TOKEN", "test-token")
	t.Setenv("TG_CHAT", "12345")

	var got telegramMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bottest-token/sendMessage" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	sink, err := NewTelegramSink(config.ActivationSinkConfig{
		Type:       "telegram",
		TokenEnv:   "TG_TOKEN",
		ChatIDEnv:  "TG_CHAT",
		APIBaseURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	defer sink.Close(context.Background())

	ev := &Event{
		Timestamp: time.Date(2026, 2, 2, 12, 34, 56, 0, time.UTC),
		RequestID: "req_123",
		Meta: ActivationMeta{
			ProjectID: "demo",
			Mode:      ModeNonStream,
		},
		Summary: Summary{
			RequestFinal: "block",
			Categories:   []string{"prompt_injection"},
		},
		Request: RequestPayload{
			Hits: []ActionEntry{
				{Category: "prompt_injection", Action: "block"},
			},
		},
	}

	if err := sink.Deliver(context.Background(), ev); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if got.ChatID != "12345" {
		t.Fatalf("chat_id mismatch: %s", got.ChatID)
	}
	if got.DisableWebPagePreview != true {
		t.Fatalf("disable_web_page_preview expected true")
	}
	if !strings.Contains(got.Text, "Straja alert: BLOCK") {
		t.Fatalf("missing alert header: %s", got.Text)
	}
	if !strings.Contains(got.Text, "request_id=req_123") {
		t.Fatalf("missing request_id: %s", got.Text)
	}
}

func TestTelegramSinkSkipsWhenActionNotAllowed(t *testing.T) {
	t.Setenv("TG_TOKEN", "test-token")
	t.Setenv("TG_CHAT", "12345")

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	sink, err := NewTelegramSink(config.ActivationSinkConfig{
		Type:          "telegram",
		TokenEnv:      "TG_TOKEN",
		ChatIDEnv:     "TG_CHAT",
		APIBaseURL:    srv.URL,
		SendOnActions: []string{"block"},
	})
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	defer sink.Close(context.Background())

	ev := &Event{
		Timestamp: time.Now().UTC(),
		RequestID: "req_warn",
		Meta: ActivationMeta{
			ProjectID: "demo",
			Mode:      ModeNonStream,
		},
		Summary: Summary{
			ResponseFinal: "warn",
		},
	}

	if err := sink.Deliver(context.Background(), ev); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected 0 calls, got %d", got)
	}
}

func TestTelegramSinkTruncatesMessage(t *testing.T) {
	t.Setenv("TG_TOKEN", "test-token")
	t.Setenv("TG_CHAT", "12345")

	var got telegramMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	sink, err := NewTelegramSink(config.ActivationSinkConfig{
		Type:          "telegram",
		TokenEnv:      "TG_TOKEN",
		ChatIDEnv:     "TG_CHAT",
		APIBaseURL:    srv.URL,
		MaxMessageLen: 80,
	})
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	defer sink.Close(context.Background())

	ev := &Event{
		Timestamp: time.Now().UTC(),
		RequestID: "req_long",
		Meta: ActivationMeta{
			ProjectID: "demo",
			Mode:      ModeNonStream,
		},
		Summary: Summary{
			RequestFinal: "block",
		},
		Request: RequestPayload{
			Hits: []ActionEntry{
				{Category: "prompt_injection", Action: "block"},
				{Category: "prompt_injection", Action: "block"},
				{Category: "jailbreak", Action: "block"},
				{Category: "pii", Action: "block"},
			},
		},
	}

	if err := sink.Deliver(context.Background(), ev); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(got.Text) > 80 {
		t.Fatalf("message not truncated: %d", len(got.Text))
	}
	if !strings.Contains(got.Text, "(truncated)") {
		t.Fatalf("missing truncation suffix: %s", got.Text)
	}
	if !strings.Contains(got.Text, "request_id=req_long") {
		t.Fatalf("missing request_id: %s", got.Text)
	}
}

func TestTelegramSinkHandlesOkFalse(t *testing.T) {
	t.Setenv("TG_TOKEN", "test-token")
	t.Setenv("TG_CHAT", "12345")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"description":"bad"}`))
	}))
	defer srv.Close()

	sink, err := NewTelegramSink(config.ActivationSinkConfig{
		Type:       "telegram",
		TokenEnv:   "TG_TOKEN",
		ChatIDEnv:  "TG_CHAT",
		APIBaseURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	defer sink.Close(context.Background())

	ev := &Event{
		Timestamp: time.Now().UTC(),
		RequestID: "req_123",
		Meta: ActivationMeta{
			ProjectID: "demo",
			Mode:      ModeNonStream,
		},
		Summary: Summary{
			RequestFinal: "block",
		},
	}

	if err := sink.Deliver(context.Background(), ev); err == nil {
		t.Fatalf("expected error")
	}
}

func TestTelegramSinkMissingEnv(t *testing.T) {
	_, err := NewTelegramSink(config.ActivationSinkConfig{
		Type:      "telegram",
		TokenEnv:  "MISSING_TOKEN",
		ChatIDEnv: "MISSING_CHAT",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}
