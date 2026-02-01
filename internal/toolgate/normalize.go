package toolgate

import (
	"regexp"
	"strings"
)

var (
	reBackslashEscape = regexp.MustCompile(`\\(.)`)
	reAnsiCQuote      = regexp.MustCompile(`\$'`)
	reCmdSub          = regexp.MustCompile(`\$\([^)]*\)`)
	reBacktickBlock   = regexp.MustCompile("`[^`]*`")
	reVarBraced       = regexp.MustCompile(`\$\{[^}]*\}`)
	reVarSimple       = regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*`)
)

// NormalizeShellCommand applies a simple normalization to reduce shell bypass tricks.
func NormalizeShellCommand(cmd string) string {
	if cmd == "" {
		return ""
	}
	out := cmd
	// Replace backslash escapes like \x with x.
	out = reBackslashEscape.ReplaceAllString(out, "$1")
	// Remove ANSI-C quoting prefix ($'...').
	out = reAnsiCQuote.ReplaceAllString(out, "'")
	// Remove command substitutions.
	out = reCmdSub.ReplaceAllString(out, "")
	out = reBacktickBlock.ReplaceAllString(out, "")
	// Remove variable references.
	out = reVarBraced.ReplaceAllString(out, "")
	out = reVarSimple.ReplaceAllString(out, "")
	// Remove quotes.
	out = strings.NewReplacer("'", "", `"`, "", "`", "").Replace(out)
	// Collapse whitespace.
	fields := strings.Fields(out)
	return strings.Join(fields, " ")
}
