package safety

import (
	"slices"
	"strings"

	"github.com/straja-ai/straja/internal/config"
)

// EvaluateAllCategories merges detection signals into policy hits across all categories.
func EvaluateAllCategories(signals []DetectionSignal, cfg config.SecurityConfig) []PolicyHit {
	hits := []PolicyHit{}

	if hit := EvaluateCategory("prompt_injection", signals, cfg.PromptInj); hit != nil {
		hits = append(hits, *hit)
	}
	if hit := EvaluateCategory("jailbreak", signals, cfg.Jailbreak); hit != nil {
		hits = append(hits, *hit)
	}
	if hit := EvaluateCategory("data_exfil", signals, cfg.DataExfil); hit != nil {
		hits = append(hits, *hit)
	}
	if hit := EvaluatePII(signals, cfg.PII); hit != nil {
		hits = append(hits, *hit)
	}
	if hit := EvaluateSecrets(signals, cfg.Secrets); hit != nil {
		hits = append(hits, *hit)
	}

	return hits
}

// EvaluateCategory handles prompt/jailbreak/exfil style categories.
func EvaluateCategory(category string, signals []DetectionSignal, cfg config.SecurityCategoryConfig) *PolicyHit {
	if category == "" {
		return nil
	}

	var (
		regexHit bool
		mlConf   float32
		sources  []string
	)

	for _, s := range signals {
		if !categoryMatches(category, s.Category) {
			continue
		}
		if s.Source == "regex" && cfg.RegexEnabled {
			regexHit = true
			if !slices.Contains(sources, s.Source) {
				sources = append(sources, s.Source)
			}
		}
		if s.Source == "ml_strajaguard_v1" && cfg.MLEnabled {
			if s.Confidence > mlConf {
				mlConf = s.Confidence
			}
			if !slices.Contains(sources, s.Source) {
				sources = append(sources, s.Source)
			}
		}
	}

	if regexHit && cfg.ActionOnRegexHit != "" {
		return &PolicyHit{
			Category:   category,
			Action:     cfg.ActionOnRegexHit,
			Confidence: 1.0,
			Sources:    sources,
		}
	}

	if regexHit && cfg.ActionOnRegexHit == "" && cfg.ActionOnBlock != "" {
		return &PolicyHit{
			Category:   category,
			Action:     cfg.ActionOnBlock,
			Confidence: 1.0,
			Sources:    sources,
		}
	}

	if cfg.MLEnabled && mlConf >= cfg.MLBlockThreshold && cfg.MLBlockThreshold > 0 {
		return &PolicyHit{
			Category:   category,
			Action:     cfg.ActionOnBlock,
			Confidence: mlConf,
			Sources:    sources,
		}
	}

	if cfg.MLEnabled && mlConf >= cfg.MLWarnThreshold && cfg.MLWarnThreshold > 0 {
		return &PolicyHit{
			Category:   category,
			Action:     "warn",
			Confidence: mlConf,
			Sources:    sources,
		}
	}

	return nil
}

// EvaluatePII merges regex and ML personal data signals.
func EvaluatePII(signals []DetectionSignal, cfg config.PIICategoryConfig) *PolicyHit {
	var (
		regexHit bool
		mlConf   float32
		sources  []string
	)
	for _, s := range signals {
		if strings.HasPrefix(s.Category, "pii") && cfg.RegexEnabled && s.Source == "regex" {
			regexHit = true
			if !slices.Contains(sources, s.Source) {
				sources = append(sources, s.Source)
			}
		}
		if (s.Category == "contains_personal_data" || s.Category == "pii") && cfg.MLEnabled && s.Source == "ml_strajaguard_v1" {
			if s.Confidence > mlConf {
				mlConf = s.Confidence
			}
			if !slices.Contains(sources, s.Source) {
				sources = append(sources, s.Source)
			}
		}
	}

	if regexHit && cfg.ActionOnRegexHit != "" {
		return &PolicyHit{
			Category:   "pii",
			Action:     cfg.ActionOnRegexHit,
			Confidence: 1.0,
			Sources:    sources,
		}
	}
	if cfg.MLEnabled && mlConf >= cfg.MLWarnThreshold && cfg.MLWarnThreshold > 0 {
		return &PolicyHit{
			Category:   "pii",
			Action:     cfg.ActionOnMLOnly,
			Confidence: mlConf,
			Sources:    sources,
		}
	}
	return nil
}

// EvaluateSecrets merges regex and ML secret signals.
func EvaluateSecrets(signals []DetectionSignal, cfg config.SecretsCategoryConfig) *PolicyHit {
	var (
		regexHit bool
		mlConf   float32
		sources  []string
	)
	for _, s := range signals {
		if strings.HasPrefix(s.Category, "secrets") && cfg.RegexEnabled && s.Source == "regex" {
			regexHit = true
			if !slices.Contains(sources, s.Source) {
				sources = append(sources, s.Source)
			}
		}
		if s.Category == "contains_secrets_maybe" && cfg.MLEnabled && s.Source == "ml_strajaguard_v1" {
			if s.Confidence > mlConf {
				mlConf = s.Confidence
			}
			if !slices.Contains(sources, s.Source) {
				sources = append(sources, s.Source)
			}
		}
	}

	if regexHit && cfg.ActionOnRegexHit != "" {
		return &PolicyHit{
			Category:   "secrets",
			Action:     cfg.ActionOnRegexHit,
			Confidence: 1.0,
			Sources:    sources,
		}
	}
	if cfg.MLEnabled && mlConf >= cfg.MLBlockThreshold && cfg.MLBlockThreshold > 0 {
		return &PolicyHit{
			Category:   "secrets",
			Action:     cfg.ActionOnRegexHit,
			Confidence: mlConf,
			Sources:    sources,
		}
	}
	if cfg.MLEnabled && mlConf >= cfg.MLWarnThreshold && cfg.MLWarnThreshold > 0 {
		return &PolicyHit{
			Category:   "secrets",
			Action:     cfg.ActionOnMLOnly,
			Confidence: mlConf,
			Sources:    sources,
		}
	}
	return nil
}

func categoryMatches(target, candidate string) bool {
	if target == candidate {
		return true
	}
	if target == "data_exfil" && candidate == "data_exfil_attempt" {
		return true
	}
	return false
}
