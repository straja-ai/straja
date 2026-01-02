package activation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WebhookSink POSTs activation events to an HTTP endpoint.
type WebhookSink struct {
	url     string
	headers map[string]string
	client  *http.Client
}

func NewWebhookSink(url string, headers map[string]string, timeout time.Duration) (*WebhookSink, error) {
	if url == "" {
		return nil, fmt.Errorf("webhook url is empty")
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	hdr := make(map[string]string, len(headers))
	for k, v := range headers {
		hdr[k] = v
	}
	return &WebhookSink{
		url:     url,
		headers: hdr,
		client: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

func (s *WebhookSink) Name() string { return "webhook:" + s.url }

func (s *WebhookSink) Deliver(ctx context.Context, ev *Event) error {
	if ev == nil {
		return nil
	}

	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}

	backoffs := []time.Duration{100 * time.Millisecond, 300 * time.Millisecond}
	var lastErr error
	for attempt := 0; attempt < len(backoffs)+1; attempt++ {
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		reqCtx := ctx
		if reqCtx == nil {
			reqCtx = context.Background()
		}
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, s.url, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range s.headers {
			req.Header.Set(k, v)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("post: %w", err)
		} else {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("status %d body=%q", resp.StatusCode, truncateBody(body))
		}

		if attempt < len(backoffs) {
			backoff := backoffs[attempt]
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
			case <-reqCtx.Done():
				timer.Stop()
				return reqCtx.Err()
			}
		}
	}

	return lastErr
}

func (s *WebhookSink) Close(context.Context) error {
	return nil
}

func truncateBody(b []byte) string {
	const limit = 200
	if len(b) <= limit {
		return string(b)
	}
	return string(b[:limit]) + "..."
}
