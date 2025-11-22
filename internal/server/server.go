package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/straja-ai/straja/internal/auth"
	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/policy"
	"github.com/straja-ai/straja/internal/provider"
)

// Server wraps the HTTP server components for Straja.
type Server struct {
	mux      *http.ServeMux
	cfg      *config.Config
	auth     *auth.Auth
	policy   policy.Engine
	provider provider.Provider // default provider for now; later per-project routing
}

// New creates a new Straja server with all routes registered.
func New(cfg *config.Config, authz *auth.Auth) *Server {
	mux := http.NewServeMux()

	pol := policy.NewBasic()

	prov, err := buildProviderFromConfig(cfg)
	if err != nil {
		log.Printf("warning: failed to build provider from config: %v", err)
		log.Printf("falling back to echo provider")
		prov = provider.NewEcho()
	}

	s := &Server{
		mux:      mux,
		cfg:      cfg,
		auth:     authz,
		policy:   pol,
		provider: prov,
	}

	// Routes
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions)

	return s
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

type openAIErrorBody struct {
	Error openAIErrorDetail `json:"error"`
}

type openAIErrorDetail struct {
	Message string      `json:"message"`
	Type    string      `json:"type"`
	Code    interface{} `json:"code,omitempty"`
}

func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 0) Auth: extract API key and map to project
	apiKey, ok := parseBearerToken(r.Header.Get("Authorization"))
	if !ok || apiKey == "" {
		writeOpenAIError(w, http.StatusUnauthorized, "Invalid or missing API key", "authentication_error")
		return
	}

	project, ok := s.auth.Lookup(apiKey)
	if !ok {
		writeOpenAIError(w, http.StatusUnauthorized, "Invalid API key", "authentication_error")
		return
	}

	var reqBody chatCompletionRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// 1) Normalize HTTP/OpenAI request → internal inference.Request
	infReq := normalizeToInferenceRequest(project.ID, &reqBody)

	// 2) Pre-LLM policy hook (BeforeModel)
	if err := s.policy.BeforeModel(ctx, infReq); err != nil {
		// Later we’ll return more detailed policy info
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (before model)", "policy_error")
		return
	}

	// 3) Call upstream provider (for now, default provider, later per-project routing).
	infResp, err := s.provider.ChatCompletion(ctx, infReq)
	if err != nil {
		log.Printf("provider error: %v", err)
		writeOpenAIError(w, http.StatusBadGateway, "Upstream provider error", "provider_error")
		return
	}

	// 4) Post-LLM policy hook (AfterModel)
	if err := s.policy.AfterModel(ctx, infReq, infResp); err != nil {
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (after model)", "policy_error")
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
func normalizeToInferenceRequest(projectID string, req *chatCompletionRequest) *inference.Request {
	msgs := make([]inference.Message, 0, len(req.Messages))
	for _, m := range req.Messages {
		msgs = append(msgs, inference.Message{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	return &inference.Request{
		ProjectID: projectID,
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

// parseBearerToken extracts the token from an Authorization: Bearer header.
func parseBearerToken(h string) (string, bool) {
	if h == "" {
		return "", false
	}
	parts := strings.Fields(h)
	if len(parts) != 2 {
		return "", false
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	return parts[1], true
}

// writeOpenAIError writes an OpenAI-style error JSON.
func writeOpenAIError(w http.ResponseWriter, status int, message, typ string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(openAIErrorBody{
		Error: openAIErrorDetail{
			Message: message,
			Type:    typ,
		},
	})
}
