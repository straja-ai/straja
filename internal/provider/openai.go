package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/straja-ai/straja/internal/inference"
)

// openAIProvider implements Provider for the OpenAI Chat Completions API.
type openAIProvider struct {
	baseURL          string
	apiKey           string
	client           *http.Client
	maxResponseBytes int64
}

// NewOpenAI creates a new OpenAI provider.
func NewOpenAI(baseURL, apiKey string, timeout time.Duration, maxResponseBytes int64) Provider {
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if maxResponseBytes <= 0 {
		maxResponseBytes = 4 * 1024 * 1024
	}

	return &openAIProvider{
		baseURL:          baseURL,
		apiKey:           apiKey,
		maxResponseBytes: maxResponseBytes,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

type openAIChatRequest struct {
	Model    string              `json:"model"`
	Messages []openAIChatMessage `json:"messages"`
	Stream   bool                `json:"stream,omitempty"`
}

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatResponse struct {
	ID      string             `json:"id"`
	Object  string             `json:"object"`
	Choices []openAIChatChoice `json:"choices"`
	Usage   openAIChatUsage    `json:"usage"`
}

type openAIChatChoice struct {
	Index        int               `json:"index"`
	Message      openAIChatMessage `json:"message"`
	FinishReason string            `json:"finish_reason"`
}

type openAIChatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openAIErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    any    `json:"code"`
	} `json:"error"`
}

func (p *openAIProvider) ChatCompletion(ctx context.Context, req *inference.Request) (*inference.Response, error) {
	// Map internal request → OpenAI payload
	oaiReq := openAIChatRequest{
		Model:    req.Model,
		Messages: make([]openAIChatMessage, 0, len(req.Messages)),
		Stream:   false, // we'll add streaming later
	}

	for _, m := range req.Messages {
		oaiReq.Messages = append(oaiReq.Messages, openAIChatMessage{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	body, err := json.Marshal(oaiReq)
	if err != nil {
		return nil, fmt.Errorf("marshal openai request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/chat/completions", p.baseURL),
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("create openai request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call openai: %w", err)
	}
	defer resp.Body.Close()

	// Handle error responses
	if resp.StatusCode >= 400 {
		limited := io.LimitReader(resp.Body, p.maxResponseBytes+1)
		respBody, err := io.ReadAll(limited)
		if err != nil {
			return nil, fmt.Errorf("openai error status %d and failed to read error body: %w", resp.StatusCode, err)
		}
		if int64(len(respBody)) > p.maxResponseBytes {
			return nil, fmt.Errorf("openai error body exceeded limit (%d bytes)", p.maxResponseBytes)
		}

		var errBody openAIErrorResponse
		if err := json.Unmarshal(respBody, &errBody); err != nil {
			return nil, fmt.Errorf("openai error status %d and failed to decode error body: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("openai error: %s (type=%s)", errBody.Error.Message, errBody.Error.Type)
	}

	limited := io.LimitReader(resp.Body, p.maxResponseBytes+1)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("decode openai response: %w", err)
	}
	if int64(len(respBody)) > p.maxResponseBytes {
		return nil, fmt.Errorf("openai response exceeded limit (%d bytes)", p.maxResponseBytes)
	}

	var oaiResp openAIChatResponse
	if err := json.Unmarshal(respBody, &oaiResp); err != nil {
		return nil, fmt.Errorf("decode openai response: %w", err)
	}

	if len(oaiResp.Choices) == 0 {
		return nil, fmt.Errorf("openai response had no choices")
	}

	first := oaiResp.Choices[0]

	return &inference.Response{
		Message: inference.Message{
			Role:    first.Message.Role,
			Content: first.Message.Content,
		},
		Usage: inference.Usage{
			PromptTokens:     oaiResp.Usage.PromptTokens,
			CompletionTokens: oaiResp.Usage.CompletionTokens,
			TotalTokens:      oaiResp.Usage.TotalTokens,
		},
	}, nil
}
