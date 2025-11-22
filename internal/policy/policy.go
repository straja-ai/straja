package policy

import (
	"context"
	"errors"
	"log"
	"regexp"
	"strings"

	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/inference"
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
	// Simple keyword blocklist (demo knob)
	bannedWords []string

	// PII / secrets
	emailRegex *regexp.Regexp
	phoneRegex *regexp.Regexp
	ccRegex    *regexp.Regexp
	ibanRegex  *regexp.Regexp
	tokenRegex *regexp.Regexp

	// PII entity toggles
	piiEmail      bool
	piiPhone      bool
	piiCreditCard bool
	piiIBAN       bool
	piiTokens     bool

	// Injection patterns
	sqlInjectionRegex *regexp.Regexp
	cmdInjectionRegex *regexp.Regexp

	// Prompt injection / jailbreak
	promptInjectionRegex *regexp.Regexp
	jailbreakRegex       *regexp.Regexp

	// Toxicity heuristics
	toxicRegex *regexp.Regexp

	// Output redaction (for completions)
	outputRedactRegex *regexp.Regexp

	// actions per category
	bannedWordsAction     action
	piiAction             action
	injectionAction       action
	promptInjectionAction action
	jailbreakAction       action
	toxicityAction        action
}

// NewBasic builds the Basic policy engine using config.PolicyConfig.
func NewBasic(pc config.PolicyConfig) Engine {
	// PII entity toggles come directly from config (defaults are applied in config.applyDefaults).
	entities := pc.PIIEntities

	return &Basic{
		bannedWords: normalizeBannedWords(pc.BannedWordsList),

		emailRegex: regexp.MustCompile(
			`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
		),
		phoneRegex: regexp.MustCompile(
			`\+?\d[\d\s\-]{7,}\d`,
		),
		ccRegex: regexp.MustCompile(
			`\b(?:\d[ -]*?){13,16}\b`,
		),
		ibanRegex: regexp.MustCompile(
			`\b[A-Z]{2}[0-9A-Z]{13,34}\b`,
		),
		tokenRegex: regexp.MustCompile(
			`[A-Za-z0-9_\-]{20,}`,
		),

		piiEmail:      entities.Email,
		piiPhone:      entities.Phone,
		piiCreditCard: entities.CreditCard,
		piiIBAN:       entities.IBAN,
		piiTokens:     entities.Tokens,

		sqlInjectionRegex: regexp.MustCompile(
			`(?i)(union\s+select|or\s+1=1|drop\s+table|information_schema|xp_cmdshell|sleep$begin:math:text$\\d+$end:math:text$)`,
		),
		cmdInjectionRegex: regexp.MustCompile(
			`(?i)(rm\s+-rf|chmod\s+777|wget\s+http|curl\s+http|bash\s+-c|powershell\s+-command)`,
		),

		promptInjectionRegex: regexp.MustCompile(
			`(?i)(ignore\s+previous\s+instructions|forget(\s+all)?\s+previous\s+instructions|as\s+an?\s+ai\s+language\s+model|you\s+are\s+no\s+longer\s+bound\s+by|bypass\s+safety)`,
		),
		jailbreakRegex: regexp.MustCompile(
			`(?i)(do\s+anything\s+now|jailbreak|uncensored|no\s+restrictions|no\s+safety\s+rules)`,
		),

		toxicRegex: regexp.MustCompile(
			`(?i)(\bidiot\b|\bstupid\b|\bkill\s+you\b|\bhate\s+you\b)`,
		),

		outputRedactRegex: regexp.MustCompile(
			`(?i)\b(password|secret|token)\b|` +
				`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}|` +
				`[A-Za-z0-9_\-]{20,}`,
		),

		bannedWordsAction:     parseAction(pc.BannedWords, actionBlock),
		piiAction:             parseAction(pc.PII, actionBlock),
		injectionAction:       parseAction(pc.Injection, actionBlock),
		promptInjectionAction: parseAction(pc.PromptInjection, actionBlock),
		jailbreakAction:       parseAction(pc.Jailbreak, actionBlock),
		toxicityAction:        parseAction(pc.Toxicity, actionLog),
	}
}

// BeforeModel runs heuristics on the *last* user message before calling the model.
// IMPORTANT: it now evaluates ALL categories, collecting multiple hits,
// and only then decides whether to block (if any category wants to block).
func (p *Basic) BeforeModel(ctx context.Context, req *inference.Request) error {
	if len(req.Messages) == 0 {
		return nil
	}

	lastIdx := len(req.Messages) - 1
	content := req.Messages[lastIdx].Content
	lc := strings.ToLower(content)

	var shouldBlock bool
	var blockReason string

	// Helper to process one category without early-return.
	handle := func(condition bool, act action, category, reason string, redactor redactorFunc) {
		if !condition {
			return
		}
		// Record category hit
		addPolicyHit(req, category)

		switch act {
		case actionBlock:
			if !shouldBlock {
				shouldBlock = true
				blockReason = reason
			}
		case actionLog:
			log.Printf("policy hit [%s] project=%s content_preview=%q",
				category, req.ProjectID, truncatePreview(content))
		case actionRedact:
			if redactor != nil {
				sanitized := redactor(content)
				req.Messages[lastIdx].Content = sanitized
				log.Printf("policy redaction [%s] project=%s before=%q after=%q",
					category, req.ProjectID, truncatePreview(content), truncatePreview(sanitized))
				// update content/lc for subsequent checks
				content = sanitized
				lc = strings.ToLower(sanitized)
			}
		case actionIgnore:
			// do nothing
		}
	}

	// 1) Banned words
	for _, banned := range p.bannedWords {
		if strings.Contains(lc, strings.ToLower(banned)) {
			handle(true, p.bannedWordsAction, "banned_words",
				"prompt blocked due to banned content",
				p.redactBannedWords)
			break // no need to check other banned words
		}
	}

	// 2) PII / secrets
	piiHit := false
	if p.piiEmail && p.emailRegex.MatchString(content) {
		piiHit = true
	}
	if p.piiPhone && p.phoneRegex.MatchString(content) {
		piiHit = true
	}
	if p.piiCreditCard && p.ccRegex.MatchString(content) {
		piiHit = true
	}
	if p.piiIBAN && p.ibanRegex.MatchString(content) {
		piiHit = true
	}
	if p.piiTokens && p.tokenRegex.MatchString(content) {
		piiHit = true
	}

	handle(
		piiHit,
		p.piiAction,
		"pii",
		"prompt blocked due to possible PII or secrets",
		p.redactPII,
	)

	// 3) Injection (SQL + command)
	handle(
		p.sqlInjectionRegex.MatchString(lc) || p.cmdInjectionRegex.MatchString(lc),
		p.injectionAction,
		"injection",
		"prompt blocked due to possible injection attempt",
		p.redactInjection,
	)

	// 4) Prompt injection / jailbreak-like
	handle(
		p.promptInjectionRegex.MatchString(lc),
		p.promptInjectionAction,
		"prompt_injection",
		"prompt blocked or redacted due to possible prompt injection attempt",
		p.redactPromptInjection,
	)

	handle(
		p.jailbreakRegex.MatchString(lc),
		p.jailbreakAction,
		"jailbreak",
		"prompt blocked or redacted due to possible jailbreak attempt",
		p.redactJailbreak,
	)

	// 5) Toxicity heuristics
	handle(
		p.toxicRegex.MatchString(lc),
		p.toxicityAction,
		"toxicity",
		"prompt blocked or redacted due to toxic or abusive language",
		p.redactToxicity,
	)

	if shouldBlock {
		return errors.New(blockReason)
	}
	return nil
}

// AfterModel redacts obviously sensitive tokens in the model output.
// This is always applied; it's safe and conservative.
func (p *Basic) AfterModel(ctx context.Context, req *inference.Request, resp *inference.Response) error {
	if resp == nil {
		return nil
	}
	// record that output was redacted (for activation logs)
	addPolicyHit(req, "output_redaction")

	resp.Message.Content = p.outputRedactRegex.ReplaceAllString(resp.Message.Content, "[REDACTED]")
	return nil
}

// ------------------------------
// Redactors
// ------------------------------

type redactorFunc func(string) string

func truncatePreview(s string) string {
	const max = 120
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func (p *Basic) redactPII(s string) string {
	// IMPORTANT: order matters.
	// We run more specific types first to avoid generic patterns
	// (phone, IBAN) “stealing” matches.

	// 1) Tokens (very generic, so do them first)
	if p.piiTokens {
		s = p.tokenRegex.ReplaceAllString(s, "[REDACTED_TOKEN]")
	}

	// 2) Credit cards
	if p.piiCreditCard {
		s = p.ccRegex.ReplaceAllString(s, "[REDACTED_CC]")
	}

	// 3) IBANs
	if p.piiIBAN {
		s = p.ibanRegex.ReplaceAllString(s, "[REDACTED_IBAN]")
	}

	// 4) Emails
	if p.piiEmail {
		s = p.emailRegex.ReplaceAllString(s, "[REDACTED_EMAIL]")
	}

	// 5) Phone numbers (very broad, do last)
	if p.piiPhone {
		s = p.phoneRegex.ReplaceAllString(s, "[REDACTED_PHONE]")
	}

	return s
}

func (p *Basic) redactInjection(s string) string {
	s = p.sqlInjectionRegex.ReplaceAllString(s, "[REDACTED_INJECTION]")
	s = p.cmdInjectionRegex.ReplaceAllString(s, "[REDACTED_INJECTION]")
	return s
}

func (p *Basic) redactPromptInjection(s string) string {
	s = p.promptInjectionRegex.ReplaceAllString(s, "[REDACTED_PROMPT_INJECTION]")
	return s
}

func (p *Basic) redactJailbreak(s string) string {
	s = p.jailbreakRegex.ReplaceAllString(s, "[REDACTED_JAILBREAK]")
	return s
}

func (p *Basic) redactToxicity(s string) string {
	s = p.toxicRegex.ReplaceAllString(s, "[REDACTED_TOXICITY]")
	return s
}

func (p *Basic) redactBannedWords(s string) string {
	lc := strings.ToLower(s)
	out := s
	for _, w := range p.bannedWords {
		if strings.Contains(lc, strings.ToLower(w)) {
			out = strings.ReplaceAll(out, w, "[REDACTED_BANNED]")
		}
	}
	return out
}

// ------------------------------
// Policy hits helper
// ------------------------------

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

// ------------------------------
// Banned words helper
// ------------------------------

func normalizeBannedWords(words []string) []string {
	m := make(map[string]struct{})
	out := make([]string, 0, len(words))

	for _, w := range words {
		trimmed := strings.TrimSpace(w)
		if trimmed == "" {
			continue
		}
		lw := strings.ToLower(trimmed)
		if _, exists := m[lw]; exists {
			continue
		}
		m[lw] = struct{}{}
		out = append(out, trimmed)
	}

	return out
}
