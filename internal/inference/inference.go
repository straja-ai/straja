package inference

import (
	"time"

	"github.com/straja-ai/straja-gateway/internal/safety"
)

// Message is a normalized representation of a chat message.
type Message struct {
	Role       string
	Content    string
	ContentAny any
	ToolCalls  []ToolCall
	ToolCallID string
	Name       string
}

// ToolCall is a normalized tool/function call payload for chat providers.
type ToolCall struct {
	ID        string
	Type      string
	Name      string
	Arguments string
}

// Request represents a normalized inference request that Straja operates on.
type Request struct {
	RequestID  string
	ProjectID  string
	Model      string
	UserID     string
	Messages   []Message
	Tools      []ToolDef
	ToolChoice any
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
	// PIIEntities holds detected PII spans with byte offsets.
	PIIEntities []safety.PIIEntity
	// StrajaGuardDetections holds request-side ensemble + per-detector details
	// for prompt injection and jailbreak (PII stays unchanged).
	StrajaGuardDetections *safety.StrajaGuardDetections
	// PostPolicyHits captures policy categories triggered on model output.
	PostPolicyHits []string
	// PostPolicyDecisions captures merged per-category actions for output.
	PostPolicyDecisions []safety.PolicyHit
	// PostDecision captures the output enforcement result: allow | redact | blocked.
	PostDecision string
	// ResponseNote captures heuristic response guard notes.
	ResponseNote string
	// OutputPreview is a redacted preview of output for activation metadata.
	OutputPreview string
	// ToolName is set for toolgate check requests.
	ToolName string
	// ToolArgsPreview is a redacted preview of tool args for activation metadata.
	ToolArgsPreview string
	// PostCheckLatency captures time spent evaluating model output.
	PostCheckLatency time.Duration
	// PostSafetyScores holds output-side ML scores (label -> probability).
	PostSafetyScores map[string]float32
	// PostSafetyFlags contains thresholded flags for output checks.
	PostSafetyFlags []string
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
	Message      Message
	Usage        Usage
	FinishReason string
}

// ToolDef stores provider tool definitions as opaque JSON-like payloads.
type ToolDef map[string]any

// Timings holds latency measurements for key stages of request processing.
type Timings struct {
	PrePolicy   time.Duration
	Provider    time.Duration
	PostPolicy  time.Duration
	StrajaGuard time.Duration
}
