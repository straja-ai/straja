package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/somanole/straja/internal/config"
	"github.com/somanole/straja/internal/inference"
	"github.com/somanole/straja/internal/policy"
	"github.com/somanole/straja/internal/provider"
)

// Server wraps the HTTP server components for Straja.
type Server struct {
	mux      *http.ServeMux
	cfg      *config.Config
	policy   policy.Engine
	provider provider.Provider
}

func buildProviderFromConfig(cfg *config.Config) (provider.Provider, error) {
	if cfg.DefaultProvider == "" {
		return nil, errors.New("no default_provider configured")
	}

	pcfg, ok := cfg.Providers[cfg.DefaultProvider]
	if !ok {
		return nil, fmt.Errorf("default_provider %q not found in providers map", cfg.DefaultProvider)
	}

	switch pcfg.Type {
	case "openai":
		apiKey := os.Getenv(pcfg.APIKeyEnv)
		if apiKey == "" {
			return nil, fmt.Errorf("environment variable %s is empty", pcfg.APIKeyEnv)
		}
		return provider.NewOpenAI(pcfg.BaseURL, apiKey), nil
	default:
		return nil, fmt.Errorf("unsupported provider type %q", pcfg.Type)
	}
}

// New creates a new Straja server with all routes registered.
func New(cfg *config.Config) *Server {
	mux := http.NewServeMux()

	pol := policy.NewNoop() // later: real policies

	prov, err := buildProviderFromConfig(cfg)
	if err != nil {
		log.Printf("warning: failed to build provider from config: %v", err)
		log.Printf("falling back to echo provider")
		prov = provider.NewEcho()
	}

	s := &Server{
		mux:      mux,
		cfg:      cfg,
		policy:   pol,
		provider: prov,
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

// --- OpenAI-style request/response types for the HTTP layer ---

type chatCompletionRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream,omitempty"`
	// Later we'll add: user, tools, etc.
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionResponse struct {
	ID      string                 `json:"id"`
	Object  string                 `json:"object"`
	Choices []chatCompletionChoice `json:"choices"`
	Usage   chatCompletionUsage    `json:"usage"`
}

type chatCompletionChoice struct {
	Index        int         `json:"index"`
	Message      chatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
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

	var reqBody chatCompletionRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// 1) Normalize HTTP/OpenAI request → internal inference.Request
	infReq := normalizeToInferenceRequest(&reqBody)

	// 2) Pre-LLM policy hook (BeforeModel)
	if err := s.policy.BeforeModel(ctx, infReq); err != nil {
		// Later we’ll return a proper OpenAI-style error with details.
		http.Error(w, "blocked by policy (before model)", http.StatusForbidden)
		return
	}

	// 3) Call upstream provider (for now, our stub echo provider).
	infResp, err := s.provider.ChatCompletion(ctx, infReq)
	if err != nil {
		log.Printf("provider error: %v", err)
		http.Error(w, "provider error", http.StatusBadGateway)
		return
	}

	// 4) Post-LLM policy hook (AfterModel)
	if err := s.policy.AfterModel(ctx, infReq, infResp); err != nil {
		http.Error(w, "blocked by policy (after model)", http.StatusForbidden)
		return
	}

	// 5) Convert internal response → HTTP/OpenAI response
	respBody := buildChatCompletionResponse(infResp)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(respBody); err != nil {
		log.Printf("failed to write response: %v", err)
	}
}

// normalizeToInferenceRequest converts the HTTP/OpenAI payload into our internal representation.
func normalizeToInferenceRequest(req *chatCompletionRequest) *inference.Request {
	msgs := make([]inference.Message, 0, len(req.Messages))
	for _, m := range req.Messages {
		msgs = append(msgs, inference.Message{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	return &inference.Request{
		ProjectID: "", // later: derive from API key / auth
		Model:     req.Model,
		UserID:    "", // later: could be taken from request body or headers
		Messages:  msgs,
	}
}

// buildChatCompletionResponse converts an internal inference.Response into OpenAI-style JSON.
func buildChatCompletionResponse(resp *inference.Response) chatCompletionResponse {
	return chatCompletionResponse{
		ID:     "chatcmpl-straja-skeleton",
		Object: "chat.completion",
		Choices: []chatCompletionChoice{
			{
				Index: 0,
				Message: chatMessage{
					Role:    resp.Message.Role,
					Content: resp.Message.Content,
				},
				FinishReason: "stop",
			},
		},
		Usage: chatCompletionUsage{
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		},
	}
}
