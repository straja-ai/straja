package guard

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ToolCall struct {
	Name          string `json:"name"`
	ArgumentsJSON string `json:"arguments_json"`
}

type Metadata struct {
	Source    string `json:"source"`
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
}

type Redaction struct {
	Type        string `json:"type"`
	Start       int    `json:"start"`
	End         int    `json:"end"`
	Replacement string `json:"replacement"`
}

type Reason struct {
	Category   string  `json:"category"`
	Rule       string  `json:"rule"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
}

type PolicyHit struct {
	Category string `json:"category"`
	Action   string `json:"action"`
	Details  string `json:"details"`
}

type StrajaGuardInfo struct {
	Enabled      bool     `json:"enabled"`
	ModelVersion string   `json:"model_version"`
	Score        float64  `json:"score"`
	Labels       []string `json:"labels"`
}

type GuardRequestCheckRequest struct {
	RequestID string     `json:"request_id"`
	ProjectID string     `json:"project_id"`
	InputText string     `json:"input_text"`
	Messages  []Message  `json:"messages"`
	ToolCalls []ToolCall `json:"tool_calls"`
	Metadata  Metadata   `json:"metadata"`
}

type GuardRequestCheckResponse struct {
	RequestID     string          `json:"request_id"`
	Decision      string          `json:"decision"`
	Redactions    []Redaction     `json:"redactions"`
	SanitizedText *string         `json:"sanitized_text"`
	Reasons       []Reason        `json:"reasons"`
	PolicyHits    []PolicyHit     `json:"policy_hits"`
	StrajaGuard   StrajaGuardInfo `json:"strajaguard"`
}

type GuardResponseCheckRequest struct {
	RequestID  string   `json:"request_id"`
	OutputText string   `json:"output_text"`
	Metadata   Metadata `json:"metadata"`
}

type GuardResponseCheckResponse struct {
	RequestID     string          `json:"request_id"`
	Decision      string          `json:"decision"`
	Redactions    []Redaction     `json:"redactions"`
	SanitizedText *string         `json:"sanitized_text"`
	Reasons       []Reason        `json:"reasons"`
	PolicyHits    []PolicyHit     `json:"policy_hits"`
	StrajaGuard   StrajaGuardInfo `json:"strajaguard"`
}
