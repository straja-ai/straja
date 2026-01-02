package activation

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"time"

	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/redact"
	"github.com/straja-ai/straja/internal/safety"
)

// Decision is the outcome of a request from Straja's perspective.
type Decision string

const (
	DecisionAllow         Decision = "allow"
	DecisionBlockedBefore Decision = "blocked_before_policy"
	DecisionBlockedAfter  Decision = "blocked_after_policy"
	DecisionErrorProvider Decision = "error_provider"
)

// PolicyHit captures a policy category and the action taken.
type PolicyHit struct {
	Category string   `json:"category"`
	Action   string   `json:"action"`
	Reason   string   `json:"reason,omitempty"`
	Score    *float32 `json:"score,omitempty"`
	Sources  []string `json:"sources,omitempty"`
}

// PolicyDecision mirrors the per-category action that was taken.
type PolicyDecision struct {
	Category   string   `json:"category"`
	Action     string   `json:"action"`
	Confidence float32  `json:"confidence,omitempty"`
	Sources    []string `json:"sources,omitempty"`
}

// StrajaGuardPayload is attached when the local ONNX model runs.
type StrajaGuardPayload struct {
	Model  string             `json:"model"`
	Scores map[string]float32 `json:"scores,omitempty"`
	Flags  []string           `json:"flags,omitempty"`
}

// Event is the canonical activation payload.
type Event struct {
	Timestamp           time.Time           `json:"timestamp"`
	RequestID           string              `json:"request_id"`
	ProjectID           string              `json:"project_id"`
	ProviderID          string              `json:"provider_id"`
	Provider            string              `json:"provider,omitempty"` // compatibility alias
	Model               string              `json:"model,omitempty"`
	Decision            Decision            `json:"decision"`
	PolicyHits          []PolicyHit         `json:"policy_hits,omitempty"`
	PolicyHitCategories []string            `json:"policy_hit_categories,omitempty"`
	PromptPreview       string              `json:"prompt_preview,omitempty"`
	CompletionPreview   string              `json:"completion_preview,omitempty"`
	IntelStatus         string              `json:"intel_status,omitempty"`
	IntelBundleVersion  string              `json:"intel_bundle_version,omitempty"`
	IntelLastValidated  string              `json:"intel_last_validated_at,omitempty"`
	IntelCachePresent   bool                `json:"intel_cache_present,omitempty"`
	StrajaGuardStatus   string              `json:"strajaguard_status,omitempty"`
	StrajaGuardBundle   string              `json:"strajaguard_bundle_version,omitempty"`
	StrajaGuard         *StrajaGuardPayload `json:"strajaguard,omitempty"`
	PolicyDecisions     []PolicyDecision    `json:"policy_decisions,omitempty"`
	SafetyScores        map[string]float32  `json:"safety_scores,omitempty"`
	SafetyThresholds    map[string]float32  `json:"safety_thresholds,omitempty"`
	LatenciesMillis     map[string]float64  `json:"latencies_ms,omitempty"`
	Extras              map[string]any      `json:"extras,omitempty"`
}

// BuildParams collects inputs needed to assemble a canonical activation event.
type BuildParams struct {
	Request              *inference.Request
	Response             *inference.Response
	ProviderName         string
	Decision             Decision
	LoggingLevel         string
	IntelStatus          string
	IntelBundleVersion   string
	IntelLastValidatedAt string
	IntelCachePresent    bool
	StrajaGuardStatus    string
	StrajaGuardBundleVer string
	SecurityThresholds   map[string]float32
	IncludeStrajaGuard   bool
	RequestID            string
}

// BuildEvent creates a canonical activation event from an inference request/response pair.
func BuildEvent(params BuildParams) *Event {
	if params.Request == nil {
		return nil
	}

	promptPreview, completionPreview := buildPreviews(params.LoggingLevel, params.Request, params.Response)

	ev := &Event{
		Timestamp:           time.Now().UTC(),
		RequestID:           ensureRequestID(params.RequestID),
		ProjectID:           params.Request.ProjectID,
		ProviderID:          params.ProviderName,
		Provider:            params.ProviderName,
		Model:               params.Request.Model,
		Decision:            params.Decision,
		PolicyHits:          buildPolicyHits(params.Request.PolicyDecisions),
		PolicyHitCategories: cloneStrings(params.Request.PolicyHits),
		PromptPreview:       redact.String(promptPreview),
		CompletionPreview:   redact.String(completionPreview),
		IntelStatus:         params.IntelStatus,
		IntelBundleVersion:  params.IntelBundleVersion,
		IntelLastValidated:  params.IntelLastValidatedAt,
		IntelCachePresent:   params.IntelCachePresent,
		StrajaGuardStatus:   params.StrajaGuardStatus,
		StrajaGuardBundle:   params.StrajaGuardBundleVer,
		PolicyDecisions:     buildPolicyDecisions(params.Request.PolicyDecisions),
		SafetyScores:        cloneFloatMap(params.Request.SecurityScores),
		SafetyThresholds:    cloneFloatMap(params.SecurityThresholds),
		LatenciesMillis:     buildLatencies(params.Request.Timings),
	}

	if params.IncludeStrajaGuard {
		if sg := buildStrajaGuard(params.Request); sg != nil {
			ev.StrajaGuard = sg
		}
	}

	return ev
}

// LogEvent prints a redacted JSON representation of the activation event.
func LogEvent(ev *Event) {
	if ev == nil {
		return
	}
	data, err := json.Marshal(ev)
	if err != nil {
		redact.Logf("activation: failed to marshal event: %v", err)
		return
	}
	redact.Logf("activation: %s", string(data))
}

func ensureRequestID(id string) string {
	if id != "" {
		return id
	}
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return hex.EncodeToString(buf[:])
	}
	return hex.EncodeToString(buf[:])
}

func buildPolicyHits(hits []safety.PolicyHit) []PolicyHit {
	if len(hits) == 0 {
		return nil
	}
	out := make([]PolicyHit, 0, len(hits))
	for _, h := range hits {
		hit := PolicyHit{
			Category: h.Category,
			Action:   h.Action,
			Sources:  cloneStrings(h.Sources),
		}
		if h.Confidence != 0 {
			c := h.Confidence
			hit.Score = &c
		}
		out = append(out, hit)
	}
	return out
}

func buildPolicyDecisions(hits []safety.PolicyHit) []PolicyDecision {
	if len(hits) == 0 {
		return nil
	}
	out := make([]PolicyDecision, 0, len(hits))
	for _, h := range hits {
		out = append(out, PolicyDecision{
			Category:   h.Category,
			Action:     h.Action,
			Confidence: h.Confidence,
			Sources:    cloneStrings(h.Sources),
		})
	}
	return out
}

func buildStrajaGuard(req *inference.Request) *StrajaGuardPayload {
	if req == nil {
		return nil
	}
	if len(req.SecurityScores) == 0 && len(req.SecurityFlags) == 0 {
		return nil
	}
	scores := cloneFloatMap(req.SecurityScores)
	return &StrajaGuardPayload{
		Model:  "strajaguard_v1",
		Scores: scores,
		Flags:  cloneStrings(req.SecurityFlags),
	}
}

func buildLatencies(t *inference.Timings) map[string]float64 {
	if t == nil {
		return nil
	}
	m := make(map[string]float64, 4)
	if t.PrePolicy > 0 {
		m["pre_policy"] = durationMillis(t.PrePolicy)
	}
	if t.Provider > 0 {
		m["provider"] = durationMillis(t.Provider)
	}
	if t.PostPolicy > 0 {
		m["post_policy"] = durationMillis(t.PostPolicy)
	}
	if t.StrajaGuard > 0 {
		m["strajaguard"] = durationMillis(t.StrajaGuard)
	}
	return m
}

func durationMillis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneFloatMap(in map[string]float32) map[string]float32 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]float32, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

var (
	emailRegex = regexp.MustCompile(`(?i)[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	tokenRegex = regexp.MustCompile(`[A-Za-z0-9_\-]{20,}`)
)

func buildPreviews(level string, req *inference.Request, resp *inference.Response) (string, string) {
	if level == "" {
		level = "metadata"
	}
	var promptPreview, completionPreview string

	switch level {
	case "full":
		if len(req.Messages) > 0 {
			last := req.Messages[len(req.Messages)-1]
			promptPreview = redact.String(truncate(last.Content, 500))
		}
		if resp != nil {
			completionPreview = redact.String(truncate(resp.Message.Content, 500))
		}
	case "redacted":
		if len(req.Messages) > 0 {
			last := req.Messages[len(req.Messages)-1]
			promptPreview = redact.String(truncate(simpleRedact(last.Content), 500))
		}
		if resp != nil {
			completionPreview = redact.String(truncate(simpleRedact(resp.Message.Content), 500))
		}
	default:
		// metadata-only: no previews
	}

	return promptPreview, completionPreview
}

func simpleRedact(s string) string {
	s = emailRegex.ReplaceAllString(s, "[REDACTED_EMAIL]")
	s = tokenRegex.ReplaceAllString(s, "[REDACTED_TOKEN]")
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
