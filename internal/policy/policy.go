package policy

import (
	"context"
	"errors"
	"log"
	"strings"

	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/intel"
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

	// actions per category
	bannedWordsAction     action
	piiAction             action
	injectionAction       action
	promptInjectionAction action
	jailbreakAction       action
	toxicityAction        action
}

// NewBasic builds the Basic policy engine using config.PolicyConfig.
func NewBasic(pc config.PolicyConfig, eng intel.Engine) Engine {
	return &Basic{
		intel: eng,

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

	handle(cats["banned_words"].Hit, p.bannedWordsAction, "banned_words",
		"prompt blocked due to banned content",
	)

	handle(cats["pii"].Hit, p.piiAction, "pii",
		"prompt blocked or redacted due to PII/secrets",
	)

	handle(cats["injection"].Hit, p.injectionAction, "injection",
		"prompt blocked or redacted due to possible injection",
	)

	handle(cats["prompt_injection"].Hit, p.promptInjectionAction, "prompt_injection",
		"prompt blocked or redacted due to possible prompt injection attempt",
	)

	handle(cats["jailbreak"].Hit, p.jailbreakAction, "jailbreak",
		"prompt blocked or redacted due to possible jailbreak attempt",
	)

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