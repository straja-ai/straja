package activation

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
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

const (
	ModeStream    = "stream"
	ModeNonStream = "non_stream"
)

// ActionEntry is a normalized per-category action/hit.
type ActionEntry struct {
	Category   string   `json:"category"`
	Action     string   `json:"action"`
	Confidence float32  `json:"confidence,omitempty"`
	Sources    []string `json:"sources,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`
}

type Summary struct {
	RequestFinal  string   `json:"request_final"`
	ResponseFinal string   `json:"response_final"`
	ResponseNote  *string  `json:"response_note"`
	Blocked       bool     `json:"blocked"`
	Categories    []string `json:"categories"`
}

type RequestDecision struct {
	Final            string        `json:"final"`
	ReasonCategories []string      `json:"reason_categories,omitempty"`
	Actions          []ActionEntry `json:"actions,omitempty"`
}

type RequestPreview struct {
	Prompt string `json:"prompt"`
}

type RequestPayload struct {
	Decision  RequestDecision    `json:"decision"`
	Preview   RequestPreview     `json:"preview"`
	Hits      []ActionEntry      `json:"hits,omitempty"`
	Scores    map[string]float32 `json:"scores,omitempty"`
	LatencyMs float64            `json:"latency_ms"`
}

type ResponseDecision struct {
	Final            string        `json:"final"`
	Note             *string       `json:"note"`
	ReasonCategories []string      `json:"reason_categories,omitempty"`
	Actions          []ActionEntry `json:"actions,omitempty"`
}

type ResponsePreview struct {
	Output string `json:"output"`
}

type ResponsePayload struct {
	Decision  ResponseDecision   `json:"decision"`
	Preview   ResponsePreview    `json:"preview"`
	Hits      []ActionEntry      `json:"hits,omitempty"`
	Scores    map[string]float32 `json:"scores,omitempty"`
	LatencyMs float64            `json:"latency_ms"`
}

type ActivationMeta struct {
	ProjectID  string `json:"project_id"`
	ProviderID string `json:"provider_id"`
	Provider   string `json:"provider"`
	Model      string `json:"model"`
	Mode       string `json:"mode"`
}

type StrajaGuardInfo struct {
	Status        string `json:"status"`
	BundleVersion string `json:"bundle_version,omitempty"`
	Model         string `json:"model,omitempty"`
}

type ActivationThresholds struct {
	Warn  float32 `json:"warn,omitempty"`
	Block float32 `json:"block,omitempty"`
}

type ActivationIntel struct {
	Status          string                          `json:"status"`
	BundleVersion   string                          `json:"bundle_version,omitempty"`
	LastValidatedAt string                          `json:"last_validated_at,omitempty"`
	CachePresent    bool                            `json:"cache_present"`
	StrajaGuard     *StrajaGuardInfo                `json:"strajaguard,omitempty"`
	Thresholds      map[string]ActivationThresholds `json:"thresholds,omitempty"`
}

type ActivationTimingMs struct {
	Provider float64 `json:"provider"`
	Total    float64 `json:"total"`
}

// Event is the canonical activation payload.
type Event struct {
	Version   string             `json:"version"`
	Timestamp time.Time          `json:"timestamp"`
	RequestID string             `json:"request_id"`
	Meta      ActivationMeta     `json:"meta"`
	Summary   Summary            `json:"summary"`
	Request   RequestPayload     `json:"request"`
	Response  ResponsePayload    `json:"response"`
	Intel     ActivationIntel    `json:"intel"`
	TimingMs  ActivationTimingMs `json:"timing_ms"`
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
	StrajaGuardModel     string
	SecurityThresholds   map[string]float32
	IncludeStrajaGuard   bool
	RequestID            string
	Mode                 string
}

// BuildEvent creates a canonical activation event from an inference request/response pair.
func BuildEvent(params BuildParams) *Event {
	if params.Request == nil {
		return nil
	}

	mode := strings.TrimSpace(strings.ToLower(params.Mode))
	if mode == "" {
		mode = ModeNonStream
	}

	promptPreview, completionPreview := buildPreviews(params.LoggingLevel, params.Request, params.Response)
	outputPreview := params.Request.OutputPreview
	if outputPreview == "" {
		outputPreview = completionPreview
	}

	requestHits := buildActionEntries(params.Request.PolicyDecisions)
	responseHits := buildActionEntries(params.Request.PostPolicyDecisions)

	requestScores := cloneFloatMap(params.Request.SecurityScores)
	responseScores := cloneFloatMap(params.Request.PostSafetyScores)

	requestLatencyMs := durationMillisFromTimings(params.Request.Timings, func(t *inference.Timings) time.Duration {
		return t.PrePolicy
	})
	providerMs := durationMillisFromTimings(params.Request.Timings, func(t *inference.Timings) time.Duration {
		return t.Provider
	})
	responseLatencyMs := durationMillisFromTimings(params.Request.Timings, func(t *inference.Timings) time.Duration {
		return t.PostPolicy
	}) + durationMillis(params.Request.PostCheckLatency)
	totalMs := requestLatencyMs + providerMs + responseLatencyMs

	requestFinal := deriveRequestFinal(params.Decision, requestHits)
	responseFinal, responseNote := deriveResponseFinal(params.Decision, mode, params.Request.PostDecision, responseHits, responseScores, responseLatencyMs, params.Request.ResponseNote)

	requestReasons := buildReasonCategories(requestHits)
	responseReasons := buildReasonCategories(responseHits)
	categories := unionCategories(requestReasons, responseReasons)

	intel := ActivationIntel{
		Status:          params.IntelStatus,
		BundleVersion:   params.IntelBundleVersion,
		LastValidatedAt: params.IntelLastValidatedAt,
		CachePresent:    params.IntelCachePresent,
		Thresholds:      buildThresholds(params.SecurityThresholds),
	}
	if params.IncludeStrajaGuard || params.StrajaGuardStatus != "" || params.StrajaGuardBundleVer != "" {
		model := strings.TrimSpace(params.StrajaGuardModel)
		if model == "" {
			model = "strajaguard_v1"
		}
		intel.StrajaGuard = &StrajaGuardInfo{
			Status:        params.StrajaGuardStatus,
			BundleVersion: params.StrajaGuardBundleVer,
			Model:         model,
		}
	}

	return &Event{
		Version:   "2",
		Timestamp: time.Now().UTC(),
		RequestID: ensureRequestID(params.RequestID),
		Meta: ActivationMeta{
			ProjectID:  params.Request.ProjectID,
			ProviderID: params.ProviderName,
			Provider:   params.ProviderName,
			Model:      params.Request.Model,
			Mode:       mode,
		},
		Summary: Summary{
			RequestFinal:  requestFinal,
			ResponseFinal: responseFinal,
			ResponseNote:  responseNote,
			Blocked:       requestFinal == "block",
			Categories:    categories,
		},
		Request: RequestPayload{
			Decision: RequestDecision{
				Final:            requestFinal,
				ReasonCategories: requestReasons,
				Actions:          requestHits,
			},
			Preview: RequestPreview{
				Prompt: redact.String(promptPreview),
			},
			Hits:      requestHits,
			Scores:    requestScores,
			LatencyMs: requestLatencyMs,
		},
		Response: ResponsePayload{
			Decision: ResponseDecision{
				Final:            responseFinal,
				Note:             responseNote,
				ReasonCategories: responseReasons,
				Actions:          responseHits,
			},
			Preview: ResponsePreview{
				Output: redact.String(outputPreview),
			},
			Hits:      responseHits,
			Scores:    responseScores,
			LatencyMs: responseLatencyMs,
		},
		Intel:    intel,
		TimingMs: ActivationTimingMs{Provider: providerMs, Total: totalMs},
	}
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

func buildActionEntries(hits []safety.PolicyHit) []ActionEntry {
	if len(hits) == 0 {
		return nil
	}
	out := make([]ActionEntry, 0, len(hits))
	for _, h := range hits {
		out = append(out, ActionEntry{
			Category:   h.Category,
			Action:     h.Action,
			Confidence: h.Confidence,
			Sources:    cloneStrings(h.Sources),
			Evidence:   h.Evidence,
		})
	}
	return out
}

func durationMillis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func durationMillisFromTimings(t *inference.Timings, pick func(*inference.Timings) time.Duration) float64 {
	if t == nil || pick == nil {
		return 0
	}
	return durationMillis(pick(t))
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

func buildThresholds(flat map[string]float32) map[string]ActivationThresholds {
	if len(flat) == 0 {
		return nil
	}
	out := make(map[string]ActivationThresholds)
	for key, val := range flat {
		if val <= 0 {
			continue
		}
		parts := strings.SplitN(key, ".", 2)
		if len(parts) != 2 {
			continue
		}
		category := strings.TrimSpace(parts[0])
		kind := strings.TrimSpace(parts[1])
		if category == "" || kind == "" {
			continue
		}
		entry := out[category]
		switch kind {
		case "warn":
			entry.Warn = val
		case "block":
			entry.Block = val
		default:
			continue
		}
		out[category] = entry
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func deriveRequestFinal(decision Decision, hits []ActionEntry) string {
	switch decision {
	case DecisionBlockedBefore:
		return "block"
	case DecisionErrorProvider:
		return "allow"
	case DecisionBlockedAfter, DecisionAllow:
		// continue
	}
	if hasAction(hits, "redact") {
		return "redact"
	}
	return "allow"
}

func deriveResponseFinal(decision Decision, mode, postDecision string, hits []ActionEntry, scores map[string]float32, latencyMs float64, noteOverride string) (string, *string) {
	postDecision = strings.ToLower(strings.TrimSpace(postDecision))
	if decision == DecisionBlockedBefore || decision == DecisionBlockedAfter || decision == DecisionErrorProvider {
		if noteOverride != "" {
			return "block", strPtr(noteOverride)
		}
		return "block", nil
	}
	if postDecision == "redacted" {
		if mode == ModeStream {
			return "allow", strPtr("redaction_suggested")
		}
		return "redact", strPtr("redaction_applied")
	}

	postCheckRan := latencyMs > 0 || len(hits) > 0 || len(scores) > 0
	if !postCheckRan {
		if noteOverride != "" {
			if noteOverride == "unsafe_instruction_detected" {
				return "warn", strPtr(noteOverride)
			}
			return "allow", strPtr(noteOverride)
		}
		return "allow", strPtr("skipped")
	}
	if noteOverride != "" {
		if noteOverride == "unsafe_instruction_detected" {
			return "warn", strPtr(noteOverride)
		}
		return "allow", strPtr(noteOverride)
	}
	return "allow", nil
}

func strPtr(v string) *string {
	return &v
}

func hasAction(hits []ActionEntry, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	for _, h := range hits {
		if strings.Contains(strings.ToLower(h.Action), needle) {
			return true
		}
	}
	return false
}

func buildReasonCategories(entries []ActionEntry) []string {
	seen := make(map[string]struct{})
	for _, e := range entries {
		if !actionInfluencesDecision(e.Action) {
			continue
		}
		cat := strings.TrimSpace(e.Category)
		if cat == "" {
			continue
		}
		seen[cat] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func unionCategories(a, b []string) []string {
	seen := make(map[string]struct{})
	for _, v := range a {
		if v == "" {
			continue
		}
		seen[v] = struct{}{}
	}
	for _, v := range b {
		if v == "" {
			continue
		}
		seen[v] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func actionInfluencesDecision(action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		return false
	}
	return strings.Contains(action, "block") || strings.Contains(action, "redact") || strings.Contains(action, "warn")
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
