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
	Model      string              `json:"model"`
	Messages   []openAIChatMessage `json:"messages"`
	Tools      []openAITool        `json:"tools,omitempty"`
	ToolChoice any                 `json:"tool_choice,omitempty"`
	Stream     bool                `json:"stream,omitempty"`
}

type openAIChatMessage struct {
	Role       string           `json:"role"`
	Content    any              `json:"content,omitempty"`
	Name       string           `json:"name,omitempty"`
	ToolCalls  []openAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openAITool struct {
	Type     string             `json:"type"`
	Function openAIToolFunction `json:"function"`
}

type openAIToolFunction struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Parameters  any    `json:"parameters,omitempty"`
	Strict      bool   `json:"strict,omitempty"`
}

type openAIToolCall struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Function openAIToolCallFunction `json:"function"`
}

type openAIToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
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
		Model:      req.Model,
		Messages:   make([]openAIChatMessage, 0, len(req.Messages)),
		Tools:      make([]openAITool, 0, len(req.Tools)),
		ToolChoice: req.ToolChoice,
		Stream:     false, // we'll add streaming later
	}

	for _, m := range req.Messages {
		msg := openAIChatMessage{
			Role:       m.Role,
			Name:       m.Name,
			ToolCallID: m.ToolCallID,
		}
		if len(m.ToolCalls) > 0 {
			msg.ToolCalls = make([]openAIToolCall, 0, len(m.ToolCalls))
			for _, tc := range m.ToolCalls {
				msg.ToolCalls = append(msg.ToolCalls, openAIToolCall{
					ID:   tc.ID,
					Type: tc.Type,
					Function: openAIToolCallFunction{
						Name:      tc.Name,
						Arguments: tc.Arguments,
					},
				})
			}
		}
		if m.ContentAny != nil {
			msg.Content = m.ContentAny
		} else if m.Content != "" || len(m.ToolCalls) == 0 {
			msg.Content = m.Content
		}
		oaiReq.Messages = append(oaiReq.Messages, msg)
	}

	for _, t := range req.Tools {
		toolType, _ := t["type"].(string)
		f, _ := t["function"].(map[string]any)
		fn := openAIToolFunction{}
		if f != nil {
			if name, ok := f["name"].(string); ok {
				fn.Name = name
			}
			if desc, ok := f["description"].(string); ok {
				fn.Description = desc
			}
			if params, ok := f["parameters"]; ok {
				fn.Parameters = params
			}
			if strict, ok := f["strict"].(bool); ok {
				fn.Strict = strict
			}
		}
		oaiReq.Tools = append(oaiReq.Tools, openAITool{
			Type:     toolType,
			Function: fn,
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
	out := inference.Message{
		Role:    first.Message.Role,
		Content: contentToText(first.Message.Content),
	}
	if first.Message.Content != nil {
		out.ContentAny = first.Message.Content
	}
	if len(first.Message.ToolCalls) > 0 {
		out.ToolCalls = make([]inference.ToolCall, 0, len(first.Message.ToolCalls))
		for _, tc := range first.Message.ToolCalls {
			out.ToolCalls = append(out.ToolCalls, inference.ToolCall{
				ID:        tc.ID,
				Type:      tc.Type,
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
			})
		}
	}

	return &inference.Response{
		Message: out,
		Usage: inference.Usage{
			PromptTokens:     oaiResp.Usage.PromptTokens,
			CompletionTokens: oaiResp.Usage.CompletionTokens,
			TotalTokens:      oaiResp.Usage.TotalTokens,
		},
		FinishReason: first.FinishReason,
	}, nil
}

func contentToText(content any) string {
	switch v := content.(type) {
	case string:
		return v
	case []any:
		out := ""
		for _, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			text, _ := m["text"].(string)
			if text == "" {
				continue
			}
			if out != "" {
				out += "\n"
			}
			out += text
		}
		return out
	default:
		return ""
	}
}
