package intel

import (
	"context"
	"regexp"
	"strings"

	"github.com/straja-ai/straja/internal/config"
)

// RegexBundle is your first "bundle": all detection logic based on regex & keywords.
// Later this will be filled from an external .straja bundle instead of hard-coded.
type RegexBundle struct {
	id      string
	version string

	bannedWords       []string
	bannedWordRegexes []*regexp.Regexp

	// PII / secrets
	emailRegex *regexp.Regexp
	phoneRegex *regexp.Regexp
	ccRegex    *regexp.Regexp
	ibanRegex  *regexp.Regexp
	tokenRegex *regexp.Regexp

	// Prompt/SQL/command injection
	sqlInjectionRegex *regexp.Regexp
	cmdInjectionRegex *regexp.Regexp

	// Prompt injection / jailbreak
	promptInjectionRegex *regexp.Regexp
	jailbreakRegex       *regexp.Regexp

	// Toxicity heuristics
	toxicRegex *regexp.Regexp

	// Output redaction hint
	outputRedactRegex *regexp.Regexp

	// PII toggles come from config
	piiEntities config.PIIEntitiesConfig
}

// NewRegexBundle builds a bundle from policy config.
// This is where ALL the regex definitions live now.
func NewRegexBundle(pc config.PolicyConfig) *RegexBundle {
	entities := pc.PIIEntities

	bannedWords := normalizeBannedWords(pc.BannedWordsList)
	bannedWordRegexes := make([]*regexp.Regexp, 0, len(bannedWords))
	for _, w := range bannedWords {
		bannedWordRegexes = append(bannedWordRegexes, regexp.MustCompile(`(?i)`+regexp.QuoteMeta(w)))
	}

	return &RegexBundle{
		id:      "straja-intel-regex",
		version: "0.1.0",

		bannedWords:       bannedWords,
		bannedWordRegexes: bannedWordRegexes,

		emailRegex: regexp.MustCompile(
			`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
		),
		phoneRegex: regexp.MustCompile(
			`\+?\d[\d\s\-$begin:math:text$$end:math:text$]{7,}\d`,
		),
		ccRegex: regexp.MustCompile(
			`\b(?:\d[ -]*?){13,16}\b`,
		),
		ibanRegex: regexp.MustCompile(
			`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`,
		),
		tokenRegex: regexp.MustCompile(
			`[A-Za-z0-9_\-]{20,}`,
		),

		piiEntities: entities,

		sqlInjectionRegex: regexp.MustCompile(
			`(?i)(union\s+select|or\s+1=1|drop\s+table|information_schema|xp_cmdshell|sleep$begin:math:text$\\d\+$end:math:text$)`,
		),
		cmdInjectionRegex: regexp.MustCompile(
			`(?i)(rm\s+-rf|chmod\s+777|wget\s+http|curl\s+http|bash\s+-c|powershell\s+-command)`,
		),

		promptInjectionRegex: regexp.MustCompile(
			`(?i)(ignore\s+previous\s+instructions|forget(\s+all)?\s+prev.*instructions|` +
				`you\s+are\s+no\s+longer\s+bound\s+by|bypass\s+safety)`,
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
	}
}

// normalizeBannedWords is copied from policy but moved here so ALL regex/keyword logic lives in the bundle.
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

func (b *RegexBundle) Status() Status {
	return Status{
		Enabled:       true,
		BundleID:      b.id,
		BundleVersion: b.version,
	}
}

func (b *RegexBundle) AnalyzeInput(ctx context.Context, text string) (*Result, error) {
	res := &Result{
		Categories: make(map[string]CategoryResult),
	}

	lc := strings.ToLower(text)
	entities := b.piiEntities

	// 1) Banned words
	for _, banned := range b.bannedWords {
		if strings.Contains(lc, strings.ToLower(banned)) {
			res.Categories["banned_words"] = CategoryResult{
				Hit:    true,
				Score:  1.0,
				Labels: []string{"banned"},
			}
			break
		}
	}

	// 2) PII / secrets
	piiLabels := []string{}
	var secretHit bool
	if entities.Email && b.emailRegex.MatchString(text) {
		piiLabels = append(piiLabels, "pii.email")
	}
	if entities.Phone && b.phoneRegex.MatchString(text) {
		piiLabels = append(piiLabels, "pii.phone")
	}
	if entities.CreditCard && b.ccRegex.MatchString(text) {
		piiLabels = append(piiLabels, "pii.credit_card")
	}
	if entities.IBAN && b.ibanRegex.MatchString(text) {
		piiLabels = append(piiLabels, "pii.iban")
	}
	if entities.Tokens && b.tokenRegex.MatchString(text) {
		piiLabels = append(piiLabels, "pii.token")
		secretHit = true
	}
	if len(piiLabels) > 0 {
		res.Categories["pii"] = CategoryResult{
			Hit:    true,
			Score:  1.0,
			Labels: piiLabels,
		}
	}
	if secretHit {
		res.Categories["secrets"] = CategoryResult{
			Hit:    true,
			Score:  1.0,
			Labels: []string{"secrets.token"},
		}
	}

	// 3) Injection (SQL + command)
	if b.sqlInjectionRegex.MatchString(lc) || b.cmdInjectionRegex.MatchString(lc) {
		res.Categories["injection"] = CategoryResult{
			Hit:    true,
			Score:  1.0,
			Labels: []string{"injection"},
		}
	}

	// 4) Prompt injection
	if b.promptInjectionRegex.MatchString(lc) {
		res.Categories["prompt_injection"] = CategoryResult{
			Hit:    true,
			Score:  1.0,
			Labels: []string{"prompt_injection"},
		}
	}

	// 5) Jailbreak
	if b.jailbreakRegex.MatchString(lc) {
		res.Categories["jailbreak"] = CategoryResult{
			Hit:    true,
			Score:  1.0,
			Labels: []string{"jailbreak"},
		}
	}

	// 6) Toxicity
	if b.toxicRegex.MatchString(lc) {
		res.Categories["toxicity"] = CategoryResult{
			Hit:    true,
			Score:  1.0,
			Labels: []string{"toxicity"},
		}
	}

	return res, nil
}

// RedactInput applies redaction for categories that support it (banned_words, pii).
func (b *RegexBundle) RedactInput(category, text string) (string, bool) {
	if text == "" {
		return text, false
	}

	redacted := text

	switch category {
	case "banned_words":
		for _, re := range b.bannedWordRegexes {
			redacted = re.ReplaceAllString(redacted, "[REDACTED_BANNED]")
		}
	case "pii":
		if b.piiEntities.Email {
			redacted = b.emailRegex.ReplaceAllString(redacted, "[REDACTED_EMAIL]")
		}
		if b.piiEntities.Phone {
			redacted = b.phoneRegex.ReplaceAllString(redacted, "[REDACTED_PHONE]")
		}
		if b.piiEntities.CreditCard {
			redacted = b.ccRegex.ReplaceAllString(redacted, "[REDACTED_CREDIT_CARD]")
		}
		if b.piiEntities.IBAN {
			redacted = b.ibanRegex.ReplaceAllString(redacted, "[REDACTED_IBAN]")
		}
		if b.piiEntities.Tokens {
			redacted = b.tokenRegex.ReplaceAllString(redacted, "[REDACTED_TOKEN]")
		}
	case "secrets":
		if b.piiEntities.Tokens {
			redacted = b.tokenRegex.ReplaceAllString(redacted, "[REDACTED_TOKEN]")
		}
	default:
		return text, false
	}

	if redacted == text {
		return text, false
	}
	return redacted, true
}

// AnalyzeOutput is currently only used for "output_redaction" hints.
func (b *RegexBundle) AnalyzeOutput(ctx context.Context, text string) (*Result, error) {
	res := &Result{
		Categories: make(map[string]CategoryResult),
	}

	if b.outputRedactRegex.MatchString(text) {
		res.Categories["output_redaction"] = CategoryResult{
			Hit:    true,
			Score:  1.0,
			Labels: []string{"output_redaction"},
		}
	}

	return res, nil
}

func (b *RegexBundle) RedactOutput(text string) (string, bool) {
	if !b.outputRedactRegex.MatchString(text) {
		return text, false
	}

	redacted := b.outputRedactRegex.ReplaceAllString(text, "[REDACTED]")
	return redacted, redacted != text
}
