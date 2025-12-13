package policy

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/intel"
	"github.com/straja-ai/straja/internal/safety"
	"github.com/straja-ai/straja/internal/strajaguard"
)

type Engine interface {
	BeforeModel(ctx context.Context, req *inference.Request) error
	AfterModel(ctx context.Context, req *inference.Request, resp *inference.Response) error
}

// ------------------------------
// Actions
// ------------------------------

type action string

const (
	actionBlock  action = "block"
	actionLog    action = "log"
	actionIgnore action = "ignore"
	actionRedact action = "redact"
)

func parseAction(v string, def action) action {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "block":
		return actionBlock
	case "log":
		return actionLog
	case "ignore":
		return actionIgnore
	case "redact":
		return actionRedact
	default:
		return def
	}
}

// ------------------------------
// Heuristic Policy (Basic v2)
// ------------------------------

type Basic struct {
	intel intel.Engine
	sg    *strajaguard.StrajaGuardModel

	securityCfg config.SecurityConfig

	// actions per category
	bannedWordsAction     action
	piiAction             action
	injectionAction       action
	promptInjectionAction action
	jailbreakAction       action
	toxicityAction        action
}

// NewBasic builds the Basic policy engine using config.PolicyConfig.
func NewBasic(pc config.PolicyConfig, sc config.SecurityConfig, eng intel.Engine, sg *strajaguard.StrajaGuardModel) Engine {
	return &Basic{
		intel: eng,
		sg:    sg,

		securityCfg: sc,

		bannedWordsAction:     parseAction(pc.BannedWords, actionBlock),
		piiAction:             parseAction(pc.PII, actionBlock),
		injectionAction:       parseAction(pc.Injection, actionBlock),
		promptInjectionAction: parseAction(pc.PromptInjection, actionBlock),
		jailbreakAction:       parseAction(pc.Jailbreak, actionBlock),
		toxicityAction:        parseAction(pc.Toxicity, actionLog),
	}
}

// BeforeModel runs heuristics on the *last* user message before calling the model.
// It evaluates all categories via the intelligence bundle and then applies block/log/redact/ignore.
func (p *Basic) BeforeModel(ctx context.Context, req *inference.Request) error {
	if len(req.Messages) == 0 {
		return nil
	}

	lastIdx := len(req.Messages) - 1
	content := req.Messages[lastIdx].Content
	systemPrompt := extractSystemPrompt(req.Messages)

	var shouldBlock bool
	var blockReason string

	// NOTE: redaction itself is delegated to the intel bundle (no regex here).
	handle := func(hit bool, act action, category, reason string) {
		if !hit {
			return
		}
		addPolicyHit(req, category)

		switch act {
		case actionBlock:
			if !shouldBlock {
				shouldBlock = true
				blockReason = reason
			}
		case actionRedact:
			// Ask the intel engine (bundle) to perform redaction if it supports it.
			if bundle, ok := p.intel.(interface {
				RedactInput(category, text string) (string, bool)
			}); ok {
				sanitized, changed := bundle.RedactInput(category, content)
				if changed {
					req.Messages[lastIdx].Content = sanitized
					log.Printf("policy redaction [%s] project=%s before=%q after=%q",
						category, req.ProjectID, truncatePreview(content), truncatePreview(sanitized))
					content = sanitized
				}
			} else {
				log.Printf("policy: redaction requested for category=%s but intel engine does not support RedactInput; leaving content unchanged", category)
			}
		case actionLog:
			log.Printf("policy hit [%s] project=%s content=%q",
				category, req.ProjectID, truncatePreview(content))
		case actionIgnore:
			// nothing
		}
	}

	// Get detection results from bundle
	result, err := p.intel.AnalyzeInput(ctx, content)
	if err != nil {
		// conservative behaviour: log and continue without blocking
		log.Printf("intel analyze input error: %v", err)
		return nil
	}
	cats := result.Categories

	// Collect regex-based detection signals for downstream merging.
	req.DetectionSignals = append(req.DetectionSignals, detectionSignalsFromRegex(cats)...)

	// Run StrajaGuard if available.
	if p.securityCfg.Enabled && p.sg != nil {
		sgStart := time.Now()
		if res, evalErr := p.sg.Evaluate(systemPrompt, content); evalErr != nil {
			sgElapsed := time.Since(sgStart)
			if req.Timings != nil {
				req.Timings.StrajaGuard += sgElapsed
			}
			log.Printf("strajaguard evaluate failed after %s: %v", sgElapsed, evalErr)
		} else if res != nil {
			sgElapsed := time.Since(sgStart)
			req.SecurityScores = res.Scores
			req.SecurityFlags = res.Flags
			req.DetectionSignals = append(req.DetectionSignals, detectionSignalsFromML(res, p.securityCfg)...)
			if req.Timings != nil {
				req.Timings.StrajaGuard += sgElapsed
			}
			log.Printf("debug: strajaguard_inference_ms=%.2f project=%s",
				float64(sgElapsed.Microseconds())/1000, req.ProjectID)
		}
	}

	// Merge signals into per-category policy hits.
	if p.securityCfg.Enabled {
		req.PolicyDecisions = safety.EvaluateAllCategories(req.DetectionSignals, p.securityCfg)
		for _, hit := range req.PolicyDecisions {
			addPolicyHit(req, hit.Category)
			switch strings.ToLower(hit.Action) {
			case "block", "block_and_redact":
				if !shouldBlock {
					shouldBlock = true
					blockReason = "prompt blocked due to " + hit.Category
				}
				if hit.Action == "block_and_redact" || hit.Action == "redact" {
					if redacted := p.tryRedact(req, hit.Category, content); redacted != "" {
						content = redacted
						req.Messages[lastIdx].Content = redacted
					}
				}
			case "redact":
				if redacted := p.tryRedact(req, hit.Category, content); redacted != "" {
					content = redacted
					req.Messages[lastIdx].Content = redacted
				}
			case "warn":
				log.Printf("policy warn [%s] project=%s confidence=%.2f content=%q sources=%v",
					hit.Category, req.ProjectID, hit.Confidence, truncatePreview(content), hit.Sources)
			case "log":
				log.Printf("policy log [%s] project=%s confidence=%.2f content=%q sources=%v",
					hit.Category, req.ProjectID, hit.Confidence, truncatePreview(content), hit.Sources)
			}
		}
	}

	// Legacy regex-only handling for categories not yet migrated (or when security is disabled).
	handle(cats["banned_words"].Hit, p.bannedWordsAction, "banned_words",
		"prompt blocked due to banned content",
	)

	handle(cats["injection"].Hit, p.injectionAction, "injection",
		"prompt blocked or redacted due to possible injection",
	)

	if !p.securityCfg.Enabled {
		handle(cats["pii"].Hit, p.piiAction, "pii",
			"prompt blocked or redacted due to PII/secrets",
		)
		handle(cats["prompt_injection"].Hit, p.promptInjectionAction, "prompt_injection",
			"prompt blocked or redacted due to possible prompt injection attempt",
		)
		handle(cats["jailbreak"].Hit, p.jailbreakAction, "jailbreak",
			"prompt blocked or redacted due to possible jailbreak attempt",
		)
	}

	handle(cats["toxicity"].Hit, p.toxicityAction, "toxicity",
		"prompt blocked or redacted due to toxic or abusive language",
	)

	if shouldBlock {
		return errors.New(blockReason)
	}
	return nil
}

// AfterModel can redact sensitive tokens in the model output using the bundle.
// This is conservative and only applies if the intel engine signals "output_redaction".
func (p *Basic) AfterModel(ctx context.Context, req *inference.Request, resp *inference.Response) error {
	if resp == nil {
		return nil
	}

	original := resp.Message.Content

	result, err := p.intel.AnalyzeOutput(ctx, original)
	if err != nil {
		log.Printf("intel analyze output error: %v", err)
		return nil
	}

	cat, ok := result.Categories["output_redaction"]
	if !ok || !cat.Hit {
		return nil
	}

	// Ask the bundle to perform redaction (regex lives inside bundle).
	if bundle, ok := p.intel.(interface {
		RedactOutput(text string) (string, bool)
	}); ok {
		redacted, changed := bundle.RedactOutput(original)
		if changed {
			addPolicyHit(req, "output_redaction")
			resp.Message.Content = redacted
		}
	} else {
		log.Printf("policy: output redaction requested but intel engine does not support RedactOutput; leaving output unchanged")
	}

	return nil
}

// ------------------------------
// Helpers
// ------------------------------

func truncatePreview(s string) string {
	const max = 120
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// Policy hits helper
func addPolicyHit(req *inference.Request, category string) {
	if req == nil || category == "" {
		return
	}
	for _, existing := range req.PolicyHits {
		if existing == category {
			return
		}
	}
	req.PolicyHits = append(req.PolicyHits, category)
}

func detectionSignalsFromRegex(cats map[string]intel.CategoryResult) []safety.DetectionSignal {
	signals := []safety.DetectionSignal{}
	for cat, res := range cats {
		if !res.Hit {
			continue
		}
		switch cat {
		case "prompt_injection", "jailbreak", "data_exfil":
			signals = append(signals, safety.DetectionSignal{
				Category:   cat,
				Source:     "regex",
				Confidence: 1.0,
			})
		case "pii":
			for _, lbl := range res.Labels {
				category := "pii"
				if strings.Contains(lbl, "token") {
					category = "secrets"
				}
				signals = append(signals, safety.DetectionSignal{
					Category:   category,
					Source:     "regex",
					Confidence: 1.0,
					Evidence:   lbl,
				})
			}
		case "secrets":
			signals = append(signals, safety.DetectionSignal{
				Category:   "secrets",
				Source:     "regex",
				Confidence: 1.0,
			})
		case "injection":
			signals = append(signals, safety.DetectionSignal{
				Category:   "injection",
				Source:     "regex",
				Confidence: 1.0,
			})
		}
	}
	return signals
}

func detectionSignalsFromML(res *strajaguard.StrajaGuardResult, cfg config.SecurityConfig) []safety.DetectionSignal {
	signals := []safety.DetectionSignal{}
	if res == nil || res.Scores == nil {
		return signals
	}

	type entry struct {
		category string
		warn     float32
	}

	mapping := map[string]entry{
		"prompt_injection":       {category: "prompt_injection", warn: cfg.PromptInj.MLWarnThreshold},
		"jailbreak":              {category: "jailbreak", warn: cfg.Jailbreak.MLWarnThreshold},
		"data_exfil_attempt":     {category: "data_exfil_attempt", warn: cfg.DataExfil.MLWarnThreshold},
		"contains_personal_data": {category: "contains_personal_data", warn: cfg.PII.MLWarnThreshold},
		"contains_secrets_maybe": {category: "contains_secrets_maybe", warn: cfg.Secrets.MLWarnThreshold},
	}

	for label, score := range res.Scores {
		if entry, ok := mapping[label]; ok {
			if entry.warn == 0 || score >= entry.warn {
				signals = append(signals, safety.DetectionSignal{
					Category:   entry.category,
					Source:     "ml_strajaguard_v1",
					Confidence: score,
				})
			}
		}
	}
	return signals
}

func extractSystemPrompt(msgs []inference.Message) string {
	var b strings.Builder
	for _, m := range msgs {
		if m.Role == "system" {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(m.Content)
		}
	}
	return b.String()
}

func (p *Basic) tryRedact(req *inference.Request, category, content string) string {
	if req == nil || content == "" || p.intel == nil {
		return ""
	}
	bundle, ok := p.intel.(interface {
		RedactInput(category, text string) (string, bool)
	})
	if !ok {
		return ""
	}
	sanitized, changed := bundle.RedactInput(category, content)
	if changed {
		log.Printf("policy redaction [%s] project=%s before=%q after=%q",
			category, req.ProjectID, truncatePreview(content), truncatePreview(sanitized))
		return sanitized
	}
	return ""
}
