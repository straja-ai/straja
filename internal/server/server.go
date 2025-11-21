package server

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"

    "github.com/somanole/straja/internal/config"
)

// Server wraps the HTTP server components for Straja.
type Server struct {
    mux *http.ServeMux
    cfg *config.Config
}

// New creates a new Straja server with all routes registered.
func New(cfg *config.Config) *Server {
    mux := http.NewServeMux()

    s := &Server{
        mux: mux,
        cfg: cfg,
    }

    // Routes
    mux.HandleFunc("/healthz", s.handleHealth)
    mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions)

    return s
}

// Start runs the HTTP server on the given address.
func (s *Server) Start(addr string) error {
    log.Printf("Straja Gateway running on %s", addr)
    return http.ListenAndServe(addr, s.mux)
}

// --- Handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, "ok")
}

// Minimal types to parse an OpenAI-style chat completion request.
type chatCompletionRequest struct {
    Model    string           `json:"model"`
    Messages []chatMessage    `json:"messages"`
    Stream   bool             `json:"stream,omitempty"`
}

type chatMessage struct {
    Role    string `json:"role"`
    Content string `json:"content"`
}

// We'll also define a minimal response type to send back.
type chatCompletionResponse struct {
    ID      string                      `json:"id"`
    Object  string                      `json:"object"`
    Choices []chatCompletionChoice      `json:"choices"`
    Usage   chatCompletionUsage         `json:"usage"`
}

type chatCompletionChoice struct {
    Index        int               `json:"index"`
    Message      chatMessage       `json:"message"`
    FinishReason string            `json:"finish_reason"`
}

type chatCompletionUsage struct {
    PromptTokens     int `json:"prompt_tokens"`
    CompletionTokens int `json:"completion_tokens"`
    TotalTokens      int `json:"total_tokens"`
}

func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var req chatCompletionRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid JSON body", http.StatusBadRequest)
        return
    }

    // For now, this is just a stub that ignores the model/messages
    // and returns a static, OpenAI-shaped response.
    // Later we'll:
    //  - normalize to an internal InferenceRequest
    //  - run policies
    //  - call upstream providers
    //  - run post-LLM policies
    //  - emit activation events

    resp := chatCompletionResponse{
        ID:     "chatcmpl-straja-skeleton",
        Object: "chat.completion",
        Choices: []chatCompletionChoice{
            {
                Index: 0,
                Message: chatMessage{
                    Role:    "assistant",
                    Content: "Hello from Straja skeleton! (This will later proxy to a real LLM.)",
                },
                FinishReason: "stop",
            },
        },
        Usage: chatCompletionUsage{
            PromptTokens:     0,
            CompletionTokens: 0,
            TotalTokens:      0,
        },
    }

    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(resp); err != nil {
        log.Printf("failed to write response: %v", err)
    }
}