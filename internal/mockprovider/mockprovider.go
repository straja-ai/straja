package mockprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPort    = 18080
	defaultDelayMS = 50
)

// StartMockProvider launches a lightweight OpenAI-compatible mock server.
// If addr is empty, it listens on 127.0.0.1:MOCK_PROVIDER_PORT (default 18080).
// It returns a shutdown function and the base URL (e.g., http://127.0.0.1:18080).
func StartMockProvider(addr string) (func(context.Context) error, string, error) {
	if strings.TrimSpace(addr) == "" {
		port := strings.TrimSpace(os.Getenv("MOCK_PROVIDER_PORT"))
		if port == "" {
			port = fmt.Sprintf("%d", defaultPort)
		}
		addr = "127.0.0.1:" + port
	}

	delay := defaultDelayMS
	if val := strings.TrimSpace(os.Getenv("MOCK_DELAY_MS")); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil && parsed >= 0 {
			delay = parsed
		}
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("listen on %s: %w", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("mock upstream request method=%s path=%s", r.Method, r.URL.Path)

		p := r.URL.Path
		if len(p) > 1 {
			p = strings.TrimSuffix(p, "/")
		}

		// Chat completions
		if r.Method == http.MethodPost && (p == "/v1/chat/completions" || p == "/chat/completions") {
			writeChatCompletion(w, delay)
			return
		}

		// Models list
		if r.Method == http.MethodGet && (p == "/v1/models" || p == "/models") {
			writeModels(w)
			return
		}

		writeNotFoundJSON(w)
	})

	srv := &http.Server{
		Handler: mux,
	}

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("mock provider server error: %v", err)
		}
	}()

	shutdown := func(ctx context.Context) error {
		return srv.Shutdown(ctx)
	}

	baseURL := "http://" + ln.Addr().String()
	log.Printf("mock provider listening on %s (delay_ms=%d)", baseURL, delay)
	return shutdown, baseURL, nil
}

func writeNotFoundJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": "Not found",
			"type":    "invalid_request_error",
		},
	})
}

func writeChatCompletion(w http.ResponseWriter, delayMS int) {
	if delayMS > 0 {
		time.Sleep(time.Duration(delayMS) * time.Millisecond)
	}

	resp := map[string]any{
		"id":      "chatcmpl-mock",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   "mock-llm",
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": "I'm a mock provider response.",
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     5,
			"completion_tokens": 5,
			"total_tokens":      10,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeModels(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"object": "list",
		"data": []map[string]any{
			{
				"id":       "mock-llm",
				"object":   "model",
				"owned_by": "mock",
			},
		},
	})
}
