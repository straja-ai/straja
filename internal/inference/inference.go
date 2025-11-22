package inference

// Message is a normalized representation of a chat message.
type Message struct {
	Role    string
	Content string
}

// Request represents a normalized inference request that Straja operates on.
type Request struct {
	ProjectID string
	Model     string
	UserID    string
	Messages  []Message
	// PolicyHits captures which policy categories triggered for this request,
	// e.g. ["pii", "injection", "prompt_injection", "output_redaction"].
	PolicyHits []string
}

// Usage holds token accounting.
// For now it's simple, we'll enrich it when we hook up real providers.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}

// Response represents a normalized inference response.
type Response struct {
	Message Message
	Usage   Usage
}
