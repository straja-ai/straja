package redact

import (
	"fmt"
	"log"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var (
	authHeaderRe   = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*bearer\s+)([A-Za-z0-9._\-+/=]+)`)
	bearerRe       = regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9._\-+/=]+)`)
	apiKeyListRe   = regexp.MustCompile(`(?i)(api[_-]?keys?\s*[:=]\s*\[)([^\]]+)(\])`)
	apiKeyValueRe  = regexp.MustCompile(`(?i)(api[_-]?key(?:s)?\s*[:=]\s*)([A-Za-z0-9._\-+/=]+)`)
	licenseKeyRe   = regexp.MustCompile(`(?i)straja-[A-Za-z0-9-]+`)
	urlRe          = regexp.MustCompile(`https?://[^\s"'<>]+`)
	tokenishKeyRe  = regexp.MustCompile(`(?i)(key|token)\s*[:=]\s*([A-Za-z0-9._\-+/=]{6,})`)
	headerKeyRe    = regexp.MustCompile(`(?i)(x-api-key|x-straja-key)\s*[:=]\s*([A-Za-z0-9._\-+/=]+)`)
	providerKeyRe  = regexp.MustCompile(`(?i)(provider_key\s*[:=]\s*)([A-Za-z0-9._\-+/=]+)`)
	licenseFieldRe = regexp.MustCompile(`(?i)(license_key\s*[:=]\s*)(\S+)`)
)

// String redacts known secret patterns from free-form strings.
func String(s string) string {
	if s == "" {
		return s
	}

	out := s
	out = authHeaderRe.ReplaceAllString(out, "${1}[REDACTED]")
	out = bearerRe.ReplaceAllString(out, "${1}[REDACTED]")
	out = apiKeyListRe.ReplaceAllString(out, "${1}REDACTED${3}")
	out = apiKeyValueRe.ReplaceAllString(out, "${1}[REDACTED]")
	out = licenseKeyRe.ReplaceAllString(out, "STRAJA-[REDACTED]")
	out = licenseFieldRe.ReplaceAllStringFunc(out, func(s string) string {
		matches := licenseFieldRe.FindStringSubmatch(s)
		if len(matches) < 3 {
			return s
		}
		if strings.Contains(matches[2], "REDACTED") {
			return s
		}
		return matches[1] + "[REDACTED]"
	})
	out = providerKeyRe.ReplaceAllString(out, "${1}[REDACTED]")
	out = headerKeyRe.ReplaceAllString(out, "${1}[REDACTED]")
	out = tokenishKeyRe.ReplaceAllStringFunc(out, func(s string) string {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "license_key") || strings.Contains(s, "[REDACTED]") {
			return s
		}
		matches := tokenishKeyRe.FindStringSubmatch(s)
		if len(matches) < 3 {
			return s
		}
		return matches[1] + "=[REDACTED]"
	})
	out = urlRe.ReplaceAllStringFunc(out, redactURL)
	for strings.Contains(out, "[REDACTED][REDACTED]") {
		out = strings.ReplaceAll(out, "[REDACTED][REDACTED]", "[REDACTED]")
	}
	return out
}

// Any formats the value with %+v and redacts secrets.
func Any(v any) string {
	return String(fmt.Sprintf("%+v", v))
}

// Sprintf formats like fmt.Sprintf and redacts the result.
func Sprintf(format string, args ...interface{}) string {
	return String(fmt.Sprintf(format, args...))
}

// Logf prints a redacted log line.
func Logf(format string, args ...interface{}) {
	log.Print(Sprintf(format, args...))
}

// Fatalf prints a redacted fatal log line.
func Fatalf(format string, args ...interface{}) {
	log.Fatal(Sprintf(format, args...))
}

func redactURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "[REDACTED_URL]"
	}

	host := u.Host
	if strings.HasSuffix(trimmed, "/") {
		return fmt.Sprintf("%s://%s/[REDACTED_PATH]", u.Scheme, host)
	}

	base := path.Base(strings.TrimSuffix(u.Path, "/"))
	if base == "." || base == "/" || base == "" {
		return fmt.Sprintf("%s://%s/[REDACTED_PATH]", u.Scheme, host)
	}
	return fmt.Sprintf("%s://%s/%s", u.Scheme, host, base)
}
