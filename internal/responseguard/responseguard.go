package responseguard

import (
	"regexp"
	"strings"

	"github.com/straja-ai/straja/internal/redact"
	"github.com/straja-ai/straja/internal/safety"
	"github.com/straja-ai/straja/internal/toolgate"
)

type Hit struct {
	RuleID     string
	Category   string
	Action     string
	Confidence float32
	Sources    []string
	Evidence   string
}

type Result struct {
	Decision string
	Note     string
	Hits     []Hit
	RuleIDs  []string
}

func EvaluateResponse(text string, cfg Config, rules []toolgate.Rule) Result {
	if !cfg.Enabled {
		return Result{Decision: "allow"}
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "ignore" {
		return Result{Decision: "allow"}
	}

	var hits []Hit
	ruleIDs := map[string]struct{}{}

	for _, r := range rules {
		category := mapCategory(r.Category)
		if category == "" {
			continue
		}
		action := cfg.actionForCategory(category)
		if action == "ignore" {
			continue
		}
		re := compileRule(r)
		if re == nil || !re.MatchString(text) {
			continue
		}
		evidence := evidenceFromMatch(re, text)
		hits = append(hits, Hit{
			RuleID:     r.ID,
			Category:   category,
			Action:     action,
			Confidence: 1,
			Sources:    []string{"heuristic:response_guard", "rule:" + r.ID},
			Evidence:   evidence,
		})
		ruleIDs[r.ID] = struct{}{}
	}

	if matchSensitiveRead(text) {
		category := CategoryDataExfilInstruction
		action := cfg.actionForCategory(category)
		if action != "ignore" {
			hits = append(hits, Hit{
				RuleID:     "read_sensitive_files",
				Category:   category,
				Action:     action,
				Confidence: 1,
				Sources:    []string{"heuristic:response_guard", "rule:read_sensitive_files"},
				Evidence:   evidenceFromInput(text),
			})
			ruleIDs["read_sensitive_files"] = struct{}{}
		}
	}

	decision := "allow"
	for _, hit := range hits {
		if hit.Action == "warn" {
			decision = "warn"
		}
	}

	note := ""
	if decision == "warn" {
		note = "unsafe_instruction_detected"
	}

	return Result{
		Decision: decision,
		Note:     note,
		Hits:     hits,
		RuleIDs:  ruleIDList(ruleIDs),
	}
}

func ruleIDList(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

func compileRule(r toolgate.Rule) *regexp.Regexp {
	pattern := r.Pattern
	prefix := "(?s)"
	if r.CaseInsensitive {
		prefix = "(?is)"
	}
	re, err := regexp.Compile(prefix + pattern)
	if err == nil {
		return re
	}
	pattern = fixPattern(r)
	re, err = regexp.Compile(prefix + pattern)
	if err == nil {
		return re
	}
	return nil
}

func fixPattern(r toolgate.Rule) string {
	switch r.ID {
	case "rm_rf_root":
		return `rm\s+-[rR]f\s+/(?:\s|\*|$)`
	case "python_requests_post":
		return `\bpython(?:3)?\b[^;\n]-c\b[^;\n]\brequests\.post\(`
	default:
		return regexp.QuoteMeta(r.Pattern)
	}
}

func evidenceFromMatch(re *regexp.Regexp, text string) string {
	if re == nil {
		return evidenceFromInput(text)
	}
	match := re.FindString(text)
	if match == "" {
		match = text
	}
	return evidenceFromInput(match)
}

func evidenceFromInput(input string) string {
	safe := redact.String(input)
	if len(safe) <= 120 {
		return safe
	}
	return safe[:120]
}

var (
	readPrimitiveRe = regexp.MustCompile(`(?i)\b(?:cat|type|less|more|head|tail|sed|awk|grep|rg|Get-Content)\b`)
	sensitivePathRe = regexp.MustCompile(`(/\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)|/\.ssh/authorized_keys|/\.ssh/known_hosts|/\.aws/credentials|/\.aws/config|/\.kube/config|/\.docker/config\.json|/\.config/gcloud/|application_default_credentials\.json|\.env\b|\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials\b|/etc/shadow\b|/etc/passwd\b|/etc/ssh/)`)
)

func matchSensitiveRead(text string) bool {
	return readPrimitiveRe.MatchString(text) && sensitivePathRe.MatchString(text)
}

func HitsToPolicyHits(hits []Hit) []safety.PolicyHit {
	if len(hits) == 0 {
		return nil
	}
	out := make([]safety.PolicyHit, 0, len(hits))
	for _, h := range hits {
		out = append(out, safety.PolicyHit{
			Category:   h.Category,
			Action:     h.Action,
			Confidence: h.Confidence,
			Sources:    append([]string(nil), h.Sources...),
			Evidence:   h.Evidence,
		})
	}
	return out
}
