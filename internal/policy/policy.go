package policy

import (
	"context"
	"errors"
	"regexp"

	"github.com/straja-ai/straja/internal/inference"
)

type Engine interface {
	BeforeModel(ctx context.Context, req *inference.Request) error
	AfterModel(ctx context.Context, req *inference.Request, resp *inference.Response) error
}

// ------------------------------
// Basic Policy (first version)
// ------------------------------

type Basic struct {
	bannedWords []string
	redactRegex *regexp.Regexp
}

func NewBasic() Engine {
	return &Basic{
		bannedWords: []string{
			"blocked_test", // sample banned keyword
			"forbidden",    // you can add more
		},
		redactRegex: regexp.MustCompile(`(?i)\b(password|secret|token)\b`),
	}
}

// BeforeModel blocks requests containing banned words in user prompt
func (p *Basic) BeforeModel(ctx context.Context, req *inference.Request) error {
	if len(req.Messages) == 0 {
		return nil
	}
	last := req.Messages[len(req.Messages)-1]

	for _, banned := range p.bannedWords {
		if containsIgnoreCase(last.Content, banned) {
			return errors.New("prompt blocked due to banned content")
		}
	}

	return nil
}

// AfterModel redacts sensitive keywords in the LLM output
func (p *Basic) AfterModel(ctx context.Context, req *inference.Request, resp *inference.Response) error {
	resp.Message.Content = p.redactRegex.ReplaceAllString(resp.Message.Content, "[REDACTED]")
	return nil
}

// Utility
func containsIgnoreCase(s, sub string) bool {
	return regexp.MustCompile("(?i)"+regexp.QuoteMeta(sub)).FindStringIndex(s) != nil
}
