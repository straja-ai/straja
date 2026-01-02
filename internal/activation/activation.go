package activation

import (
	"context"
	"encoding/json"
	"time"

	"github.com/straja-ai/straja/internal/redact"
)

// Decision is the outcome of a request from Straja's perspective.
type Decision string

const (
	DecisionAllow         Decision = "allow"
	DecisionBlockedBefore Decision = "blocked_before_policy"
	DecisionBlockedAfter  Decision = "blocked_after_policy"
	DecisionErrorProvider Decision = "error_provider"
)

// Event is a structured activation event emitted for each LLM interaction.
type Event struct {
	Timestamp         time.Time `json:"timestamp"`
	ProjectID         string    `json:"project_id"`
	Provider          string    `json:"provider"`
	Model             string    `json:"model"`
	Decision          Decision  `json:"decision"`
	PromptPreview     string    `json:"prompt_preview"`
	CompletionPreview string    `json:"completion_preview"`
	// PolicyHits contains all policy categories that triggered for this request,
	// e.g. ["pii", "injection", "prompt_injection", "output_redaction"].
	PolicyHits []string `json:"policy_hits"`
	// IntelStatus reports whether intelligence/policy was enabled for this request.
	IntelStatus          string `json:"intel_status,omitempty"`
	IntelBundleVersion   string `json:"intel_bundle_version,omitempty"`
	IntelLastValidatedAt string `json:"intel_last_validated_at,omitempty"`
	IntelCachePresent    bool   `json:"intel_cache_present,omitempty"`
	StrajaGuardStatus    string `json:"strajaguard_status,omitempty"`
	StrajaGuardBundleVer string `json:"strajaguard_bundle_version,omitempty"`
	// StrajaGuard contains raw scores and flags from the ML classifier.
	StrajaGuard *StrajaGuardPayload `json:"strajaguard,omitempty"`
	// PolicyDecisions are the merged per-category decisions (regex + ML).
	PolicyDecisions []PolicyDecision `json:"policy_decisions,omitempty"`
}

// Emitter sends activation events to some sink (stdout, file, webhook, etc.).
type Emitter interface {
	Emit(ctx context.Context, ev *Event)
}

// StrajaGuardPayload is attached when the local ONNX model runs.
type StrajaGuardPayload struct {
	Model  string             `json:"model"`
	Scores map[string]float32 `json:"scores,omitempty"`
	Flags  []string           `json:"flags,omitempty"`
}

// PolicyDecision mirrors the per-category action that was taken.
type PolicyDecision struct {
	Category   string   `json:"category"`
	Action     string   `json:"action"`
	Confidence float32  `json:"confidence,omitempty"`
	Sources    []string `json:"sources,omitempty"`
}

// stdoutEmitter prints JSON events to stdout.
type stdoutEmitter struct{}

// NewStdout creates a new stdout-based emitter.
func NewStdout() Emitter {
	return &stdoutEmitter{}
}

func (e *stdoutEmitter) Emit(ctx context.Context, ev *Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		redact.Logf("activation: failed to marshal event: %v", err)
		return
	}
	redact.Logf("activation: %s", string(data))
}
