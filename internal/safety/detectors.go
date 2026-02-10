package safety

// DetectorResult captures one detector's output for transparency/debuggability.
//
// Score semantics:
// - Score is "attack confidence" in [0,1] where higher means more likely attack.
// - When Error is non-empty, Score should be nil.
type DetectorResult struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind,omitempty"`
	ModelRef  string   `json:"model_ref,omitempty"` // bundle-relative identifier (never an absolute path)
	Score     *float32 `json:"score,omitempty"`
	LatencyMs float64  `json:"latency_ms,omitempty"`
	Error     string   `json:"error,omitempty"`
	Version   string   `json:"version,omitempty"`
}

type EnsembleResult struct {
	Method         string  `json:"method"`
	Threshold      float32 `json:"threshold"`
	Score          float32 `json:"score"`
	Attack         bool    `json:"attack"`
	ValidDetectors int     `json:"valid_detectors"`
	TotalDetectors int     `json:"total_detectors"`
	Status         string  `json:"status"`
}

type CategoryDetections struct {
	Ensemble  EnsembleResult    `json:"ensemble"`
	Detectors []DetectorResult  `json:"detectors,omitempty"`
}

// StrajaGuardDetections is attached to activation events for request-side specialists.
// PII stays unchanged (PII entities are still exposed separately, and redaction logic remains unchanged).
type StrajaGuardDetections struct {
	PromptInjection *CategoryDetections `json:"prompt_injection,omitempty"`
	Jailbreak       *CategoryDetections `json:"jailbreak,omitempty"`
}

