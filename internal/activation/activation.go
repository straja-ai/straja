package activation

import (
	"context"
	"encoding/json"
	"log"
	"time"
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
}

// Emitter sends activation events to some sink (stdout, file, webhook, etc.).
type Emitter interface {
	Emit(ctx context.Context, ev *Event)
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
		log.Printf("activation: failed to marshal event: %v", err)
		return
	}
	log.Printf("activation: %s", string(data))
}
