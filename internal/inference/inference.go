package inference

import (
	"time"

	"github.com/straja-ai/straja/internal/safety"
)

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
	// Timings captures per-stage latency for debugging/observability.
	Timings *Timings
	// PolicyHits captures which policy categories triggered for this request,
	// e.g. ["pii", "injection", "prompt_injection", "output_redaction"].
	PolicyHits []string
	// DetectionSignals are the raw detections emitted by regex/ML layers.
	DetectionSignals []safety.DetectionSignal
	// PolicyDecisions captures the merged per-category actions.
	PolicyDecisions []safety.PolicyHit
	// SecurityScores holds raw ML scores (label -> probability) for activation payloads.
	SecurityScores map[string]float32
	// SecurityFlags contains thresholded flags (e.g. prompt_injection_high).
	SecurityFlags []string
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

// Timings holds latency measurements for key stages of request processing.
type Timings struct {
	PrePolicy   time.Duration
	Provider    time.Duration
	PostPolicy  time.Duration
	StrajaGuard time.Duration
}
