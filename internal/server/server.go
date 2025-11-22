package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/activation"
	"github.com/straja-ai/straja/internal/auth"
	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/policy"
	"github.com/straja-ai/straja/internal/provider"
)

// Server wraps the HTTP server components for Straja.
type Server struct {
	mux             *http.ServeMux
	cfg             *config.Config
	auth            *auth.Auth
	policy          policy.Engine
	providers       map[string]provider.Provider // name -> provider
	defaultProvider string                       // name of default provider
	activation      activation.Emitter
	loggingLevel    string
}

// New creates a new Straja server with all routes registered.
func New(cfg *config.Config, authz *auth.Auth) *Server {
	mux := http.NewServeMux()

	// Basic policy engine (first real policy implementation)
	pol := policy.NewBasic(cfg.Policy)

	provs, err := buildProviderRegistry(cfg)
	if err != nil {
		log.Printf("warning: failed to build providers from config: %v", err)
		log.Printf("falling back to echo provider")
		provs = map[string]provider.Provider{
			"echo": provider.NewEcho(),
		}
		if cfg.DefaultProvider == "" {
			cfg.DefaultProvider = "echo"
		}
	}

	s := &Server{
		mux:             mux,
		cfg:             cfg,
		auth:            authz,
		policy:          pol,
		providers:       provs,
		defaultProvider: cfg.DefaultProvider,
		activation:      activation.NewStdout(),
		loggingLevel:    strings.ToLower(cfg.Logging.ActivationLevel),
	}

	// Routes
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions)

	return s
}

// buildProviderRegistry constructs all configured providers.
func buildProviderRegistry(cfg *config.Config) (map[string]provider.Provider, error) {
	if len(cfg.Providers) == 0 {
		return nil, errors.New("no providers configured")
	}

	reg := make(map[string]provider.Provider, len(cfg.Providers))

	for name, pcfg := range cfg.Providers {
		switch pcfg.Type {
		case "openai":
			apiKey := os.Getenv(pcfg.APIKeyEnv)
			if apiKey == "" {
				return nil, fmt.Errorf("provider %q: environment variable %s is empty", name, pcfg.APIKeyEnv)
			}
			reg[name] = provider.NewOpenAI(pcfg.BaseURL, apiKey)
		default:
			return nil, fmt.Errorf("provider %q: unsupported type %q", name, pcfg.Type)
		}
	}

	if cfg.DefaultProvider == "" {
		return nil, errors.New("default_provider is empty")
	}
	if _, ok := reg[cfg.DefaultProvider]; !ok {
		return nil, fmt.Errorf("default_provider %q not found in providers map", cfg.DefaultProvider)
	}

	return reg, nil
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

	// Auth: extract API key and map to project
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

	// Determine provider for this project
	providerName := project.Provider
	if providerName == "" {
		providerName = s.defaultProvider
	}

	prov, ok := s.providers[providerName]
	if !ok {
		log.Printf("no provider %q for project %q", providerName, project.ID)
		writeOpenAIError(w, http.StatusInternalServerError, "Straja misconfiguration: unknown provider for project", "configuration_error")
		return
	}

	// 1) Normalize HTTP/OpenAI request → internal inference.Request
	infReq := normalizeToInferenceRequest(project.ID, &reqBody)

	// 2) Before-model block
	if err := s.policy.BeforeModel(ctx, infReq); err != nil {
		s.emitActivation(ctx, infReq, nil, providerName, activation.DecisionBlockedBefore)
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (before model)", "policy_error")
		return
	}

	// 3) Provider error
	infResp, err := prov.ChatCompletion(ctx, infReq)
	if err != nil {
		log.Printf("provider %q error: %v", providerName, err)
		s.emitActivation(ctx, infReq, nil, providerName, activation.DecisionErrorProvider)
		writeOpenAIError(w, http.StatusBadGateway, "Upstream provider error", "provider_error")
		return
	}

	// 4) After-model block
	if err := s.policy.AfterModel(ctx, infReq, infResp); err != nil {
		s.emitActivation(ctx, infReq, infResp, providerName, activation.DecisionBlockedAfter)
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (after model)", "policy_error")
		return
	}

	// 5) Success
	s.emitActivation(ctx, infReq, infResp, providerName, activation.DecisionAllow)

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

// emitActivation builds and sends an activation event via the configured emitter.
func (s *Server) emitActivation(ctx context.Context, req *inference.Request, resp *inference.Response, providerName string, decision activation.Decision) {
	if s.activation == nil || req == nil {
		return
	}

	promptPreview, completionPreview := s.buildPreviews(req, resp)

	ev := &activation.Event{
		Timestamp:         time.Now().UTC(),
		ProjectID:         req.ProjectID,
		Provider:          providerName,
		Model:             req.Model,
		Decision:          decision,
		PromptPreview:     promptPreview,
		CompletionPreview: completionPreview,
		PolicyHits:        append([]string(nil), req.PolicyHits...), // copy to be safe
	}

	s.activation.Emit(ctx, ev)
}

var (
	emailRegex = regexp.MustCompile(`(?i)[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	tokenRegex = regexp.MustCompile(`[A-Za-z0-9_\-]{20,}`)
)

func (s *Server) buildPreviews(req *inference.Request, resp *inference.Response) (string, string) {
	level := s.loggingLevel
	if level == "" {
		level = "metadata"
	}

	var promptPreview, completionPreview string

	switch level {
	case "full":
		if len(req.Messages) > 0 {
			last := req.Messages[len(req.Messages)-1]
			promptPreview = truncate(last.Content, 500)
		}
		if resp != nil {
			completionPreview = truncate(resp.Message.Content, 500)
		}
	case "redacted":
		if len(req.Messages) > 0 {
			last := req.Messages[len(req.Messages)-1]
			promptPreview = truncate(simpleRedact(last.Content), 500)
		}
		if resp != nil {
			completionPreview = truncate(simpleRedact(resp.Message.Content), 500)
		}
	default: // "metadata"
		// no previews
	}

	return promptPreview, completionPreview
}

func simpleRedact(s string) string {
	s = emailRegex.ReplaceAllString(s, "[REDACTED_EMAIL]")
	s = tokenRegex.ReplaceAllString(s, "[REDACTED_TOKEN]")
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
