package safety

// DetectionSignal captures a single detection emitted by regex or ML.
type DetectionSignal struct {
	Category   string  `json:"category"`
	Source     string  `json:"source"`
	Confidence float32 `json:"confidence"`
	Evidence   string  `json:"evidence,omitempty"`
}

// PolicyHit is the decision-ready signal fed into the policy engine.
type PolicyHit struct {
	Category   string   `json:"category"`
	Action     string   `json:"action"`
	Confidence float32  `json:"confidence"`
	Sources    []string `json:"sources"`
	Evidence   string   `json:"evidence,omitempty"`
}
