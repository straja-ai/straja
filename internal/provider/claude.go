package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/straja-ai/straja-gateway/internal/inference"
)

const defaultClaudeVersion = "2023-06-01"

type claudeProvider struct {
	baseURL          string
	apiKey           string
	client           *http.Client
	maxResponseBytes int64
}

// NewClaude creates a provider for Claude's Messages API.
func NewClaude(baseURL, apiKey string, timeout time.Duration, maxResponseBytes int64) Provider {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "https://api.anthropic.com/v1"
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if maxResponseBytes <= 0 {
		maxResponseBytes = 4 * 1024 * 1024
	}

	return &claudeProvider{
		baseURL:          strings.TrimSpace(baseURL),
		apiKey:           strings.TrimSpace(apiKey),
		maxResponseBytes: maxResponseBytes,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

type claudeMessagesRequest struct {
	Model      string          `json:"model"`
	Messages   []claudeMessage `json:"messages"`
	System     string          `json:"system,omitempty"`
	MaxTokens  int             `json:"max_tokens"`
	Stream     bool            `json:"stream,omitempty"`
	Metadata   *claudeReqMeta  `json:"metadata,omitempty"`
	Stop       []string        `json:"stop_sequences,omitempty"`
	Thinking   *map[string]any `json:"thinking,omitempty"`
	ToolChoice *map[string]any `json:"tool_choice,omitempty"`
}

type claudeReqMeta struct {
	UserID string `json:"user_id,omitempty"`
}

type claudeMessage struct {
	Role    string               `json:"role"`
	Content []claudeContentBlock `json:"content"`
}

type claudeContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type claudeMessagesResponse struct {
	Content []claudeContentBlock `json:"content"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

type claudeErrorResponse struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func (p *claudeProvider) ChatCompletion(ctx context.Context, req *inference.Request) (*inference.Response, error) {
	cReq, err := mapInferenceToClaude(req)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(cReq)
	if err != nil {
		return nil, fmt.Errorf("marshal claude request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/messages", strings.TrimRight(p.baseURL, "/")),
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("create claude request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", defaultClaudeVersion)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call claude: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		limited := io.LimitReader(resp.Body, p.maxResponseBytes+1)
		respBody, err := io.ReadAll(limited)
		if err != nil {
			return nil, fmt.Errorf("claude error status %d and failed to read error body: %w", resp.StatusCode, err)
		}
		if int64(len(respBody)) > p.maxResponseBytes {
			return nil, fmt.Errorf("claude error body exceeded limit (%d bytes)", p.maxResponseBytes)
		}

		var errBody claudeErrorResponse
		if err := json.Unmarshal(respBody, &errBody); err != nil {
			return nil, fmt.Errorf("claude error status %d and failed to decode error body: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("claude error: %s (type=%s)", errBody.Error.Message, errBody.Error.Type)
	}

	limited := io.LimitReader(resp.Body, p.maxResponseBytes+1)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("decode claude response: %w", err)
	}
	if int64(len(respBody)) > p.maxResponseBytes {
		return nil, fmt.Errorf("claude response exceeded limit (%d bytes)", p.maxResponseBytes)
	}

	var cResp claudeMessagesResponse
	if err := json.Unmarshal(respBody, &cResp); err != nil {
		return nil, fmt.Errorf("decode claude response: %w", err)
	}

	text := extractClaudeText(cResp.Content)
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("claude response had no text content")
	}

	return &inference.Response{
		Message: inference.Message{
			Role:    "assistant",
			Content: text,
		},
		Usage: inference.Usage{
			PromptTokens:     cResp.Usage.InputTokens,
			CompletionTokens: cResp.Usage.OutputTokens,
			TotalTokens:      cResp.Usage.InputTokens + cResp.Usage.OutputTokens,
		},
	}, nil
}

func mapInferenceToClaude(req *inference.Request) (*claudeMessagesRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("inference request is nil")
	}
	out := &claudeMessagesRequest{
		Model:     strings.TrimSpace(req.Model),
		Messages:  make([]claudeMessage, 0, len(req.Messages)),
		MaxTokens: 1024,
		Stream:    false,
	}
	if out.Model == "" {
		return nil, fmt.Errorf("model is required")
	}

	systemParts := []string{}
	for _, m := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(m.Role))
		content := m.Content
		switch role {
		case "system":
			if strings.TrimSpace(content) != "" {
				systemParts = append(systemParts, content)
			}
		case "assistant":
			out.Messages = append(out.Messages, claudeMessage{
				Role: "assistant",
				Content: []claudeContentBlock{
					{Type: "text", Text: content},
				},
			})
		default:
			out.Messages = append(out.Messages, claudeMessage{
				Role: "user",
				Content: []claudeContentBlock{
					{Type: "text", Text: content},
				},
			})
		}
	}
	if len(systemParts) > 0 {
		out.System = strings.Join(systemParts, "\n\n")
	}
	if len(out.Messages) == 0 {
		return nil, fmt.Errorf("at least one non-system message is required")
	}

	return out, nil
}

func extractClaudeText(blocks []claudeContentBlock) string {
	if len(blocks) == 0 {
		return ""
	}
	var b strings.Builder
	for _, block := range blocks {
		if strings.TrimSpace(block.Text) == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(block.Text)
	}
	return b.String()
}
