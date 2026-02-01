package toolgate

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/redact"
)

type ToolType string

type Action string

type Mode string

const (
	ToolTypeShell      ToolType = "shell"
	ToolTypeHTTP       ToolType = "http"
	ToolTypeFilesystem ToolType = "filesystem"

	ActionAllow Action = "allow"
	ActionBlock Action = "block"
	ActionWarn  Action = "warn"

	ModeElevatedOnly Mode = "elevated_only"
	ModeAllTools     Mode = "all_tools"
)

type ToolCall struct {
	Name string
	Type ToolType
	Args map[string]any
}

type Hit struct {
	RuleID     string   `json:"rule_id"`
	Category   string   `json:"category"`
	Action     string   `json:"action"`
	Confidence float32  `json:"confidence"`
	Sources    []string `json:"sources"`
	Evidence   string   `json:"evidence"`
}

type Result struct {
	Action Action
	Hits   []Hit
}

type Evaluator struct {
	cfg            config.ToolGateConfig
	rules          []rule
	readPrimitives *regexpWrapper
	sensitivePaths *regexpWrapper
	base64Blob     *regexpWrapper
}

type regexpWrapper struct {
	re *regexp.Regexp
}

func (r *regexpWrapper) MatchString(s string) bool {
	if r == nil || r.re == nil {
		return false
	}
	return r.re.MatchString(s)
}

func (r *regexpWrapper) FindString(s string) string {
	if r == nil || r.re == nil {
		return ""
	}
	return r.re.FindString(s)
}

// New creates a tool gate evaluator from config.
func New(cfg config.ToolGateConfig) *Evaluator {
	e := &Evaluator{cfg: cfg}
	e.rules = compileRules(buildRules())
	e.readPrimitives = &regexpWrapper{re: regexp.MustCompile(`(?i)\b(?:cat|type|less|more|head|tail|sed|awk|grep|rg|Get-Content)\b`)}
	e.sensitivePaths = &regexpWrapper{re: regexp.MustCompile(`(/\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)|/\.ssh/authorized_keys|/\.ssh/known_hosts|/\.aws/credentials|/\.aws/config|/\.kube/config|/\.docker/config\.json|/\.config/gcloud/|application_default_credentials\.json|\.env\b|\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials\b|/etc/shadow\b|/etc/passwd\b|/etc/ssh/)`)}
	e.base64Blob = &regexpWrapper{re: regexp.MustCompile(`\b[A-Za-z0-9+/]{200,}={0,2}\b`)}
	return e
}

// Evaluate applies tool-gate rules to a tool call.
func (e *Evaluator) Evaluate(call ToolCall) Result {
	if !e.cfg.Enabled {
		return Result{Action: ActionAllow}
	}
	toolType := call.Type
	if toolType == "" {
		toolType = inferToolType(call)
	}

	switch toolType {
	case ToolTypeShell:
		cmd := extractShellCommand(call)
		if strings.TrimSpace(cmd) == "" {
			return Result{Action: ActionAllow}
		}
		if e.isAllowlistedCommand(cmd) {
			return Result{Action: ActionAllow}
		}
		normalized := NormalizeShellCommand(cmd)
		return e.evaluateShell(cmd, normalized)
	case ToolTypeFilesystem:
		return e.evaluateFilesystem(call)
	case ToolTypeHTTP:
		return e.evaluateHTTP(call)
	default:
		return Result{Action: ActionAllow}
	}
}

func (e *Evaluator) evaluateShell(original, normalized string) Result {
	var hits []Hit
	for _, r := range e.rules {
		if r.AppliesTo != ToolTypeShell {
			continue
		}
		if r.re == nil {
			continue
		}
		if !r.re.MatchString(original) && !r.re.MatchString(normalized) {
			continue
		}
		action := e.ruleAction(r)
		hits = append(hits, buildHit(r, action, evidenceFromMatch(r.re, original, normalized)))
	}

	// Special rule: read_sensitive_files
	if e.matchSensitiveRead(original, normalized) {
		hits = append(hits, buildHit(rule{ID: "read_sensitive_files", Category: categoryDataExfil}, ActionBlock, evidenceFromInput(original)))
	}

	return finalizeResult(hits)
}

func (e *Evaluator) evaluateFilesystem(call ToolCall) Result {
	if !isFilesystemRead(call.Name) {
		return Result{Action: ActionAllow}
	}
	paths := extractPaths(call.Args)
	for _, p := range paths {
		if e.sensitivePaths.MatchString(p) {
			hit := buildHit(rule{ID: "read_sensitive_files", Category: categoryDataExfil}, ActionBlock, evidenceFromInput(p))
			return Result{Action: ActionBlock, Hits: []Hit{hit}}
		}
	}
	return Result{Action: ActionAllow}
}

func (e *Evaluator) evaluateHTTP(call ToolCall) Result {
	urlVal, _ := getStringArg(call.Args, "url")
	method, _ := getStringArg(call.Args, "method")
	bodyVal, _ := call.Args["body"]
	if urlVal == "" || method == "" {
		return Result{Action: ActionAllow}
	}
	methodUpper := strings.ToUpper(strings.TrimSpace(method))
	if methodUpper != "POST" && methodUpper != "PUT" && methodUpper != "PATCH" {
		return Result{Action: ActionAllow}
	}
	if hostAllowed(urlVal, e.cfg.AllowlistHosts) {
		return Result{Action: ActionAllow}
	}
	bodyStr, bodyLen := stringifyBody(bodyVal)
	if bodyLen <= 0 {
		return Result{Action: ActionAllow}
	}
	if bodyLen <= 4096 && !e.base64Blob.MatchString(bodyStr) {
		return Result{Action: ActionAllow}
	}
	// Block large or base64-ish body to non-allowlisted host.
	hit := Hit{
		RuleID:     "http_large_body_exfil",
		Category:   categoryDataExfil,
		Action:     string(ActionBlock),
		Confidence: 1,
		Sources:    []string{"heuristic:tool_gate", "rule:http_large_body_exfil"},
		Evidence:   evidenceFromInput(fmt.Sprintf("%s %s", methodUpper, urlVal)),
	}
	return Result{Action: ActionBlock, Hits: []Hit{hit}}
}

func (e *Evaluator) ruleAction(r rule) Action {
	if r.Category == categoryPrivilegeEscalate {
		if Mode(strings.ToLower(e.cfg.Mode)) == ModeAllTools {
			return ActionWarn
		}
		return ActionBlock
	}
	if r.Action != "" {
		return r.Action
	}
	if r.DefaultAction != "" {
		return r.DefaultAction
	}
	return ActionAllow
}

func finalizeResult(hits []Hit) Result {
	action := ActionAllow
	for _, h := range hits {
		if h.Action == string(ActionBlock) {
			action = ActionBlock
			break
		}
		if h.Action == string(ActionWarn) {
			action = ActionWarn
		}
	}
	return Result{Action: action, Hits: hits}
}

func buildHit(r rule, action Action, evidence string) Hit {
	return Hit{
		RuleID:     r.ID,
		Category:   r.Category,
		Action:     string(action),
		Confidence: 1,
		Sources:    []string{"heuristic:tool_gate", "rule:" + r.ID},
		Evidence:   evidence,
	}
}

func evidenceFromMatch(re *regexp.Regexp, original, normalized string) string {
	match := ""
	if re != nil {
		match = re.FindString(original)
		if match == "" {
			match = re.FindString(normalized)
		}
	}
	if match == "" {
		match = original
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

func (e *Evaluator) matchSensitiveRead(original, normalized string) bool {
	readMatch := e.readPrimitives.MatchString(original) || e.readPrimitives.MatchString(normalized)
	if !readMatch {
		return false
	}
	return e.sensitivePaths.MatchString(original) || e.sensitivePaths.MatchString(normalized)
}

func isFilesystemRead(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), "filesystem.read")
}

func inferToolType(call ToolCall) ToolType {
	name := strings.ToLower(strings.TrimSpace(call.Name))
	if strings.HasPrefix(name, "filesystem.") {
		return ToolTypeFilesystem
	}
	if strings.HasPrefix(name, "http") {
		return ToolTypeHTTP
	}
	if strings.Contains(name, "shell") || name == "bash" || name == "sh" {
		return ToolTypeShell
	}
	if name == "nodes.run" {
		if v, ok := getStringArg(call.Args, "tool_type"); ok {
			return ToolType(strings.ToLower(v))
		}
	}
	return ""
}

func extractShellCommand(call ToolCall) string {
	if v, ok := getStringArg(call.Args, "command"); ok {
		return v
	}
	if v, ok := getStringArg(call.Args, "cmd"); ok {
		return v
	}
	if v, ok := getStringArg(call.Args, "shell_command"); ok {
		return v
	}
	return ""
}

func extractPaths(args map[string]any) []string {
	if len(args) == 0 {
		return nil
	}
	var out []string
	for _, key := range []string{"path", "paths", "file", "files", "filename", "target"} {
		val, ok := args[key]
		if !ok {
			continue
		}
		switch v := val.(type) {
		case string:
			out = append(out, v)
		case []string:
			out = append(out, v...)
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func stringifyBody(body any) (string, int) {
	if body == nil {
		return "", 0
	}
	switch v := body.(type) {
	case string:
		return v, len(v)
	case []byte:
		return string(v), len(v)
	default:
		s := fmt.Sprintf("%v", body)
		return s, len(s)
	}
}

func hostAllowed(rawURL string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	host := strings.ToLower(u.Host)
	withoutPort := strings.ToLower(stripPort(u.Host))
	for _, entry := range allowlist {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if entry == host || entry == withoutPort {
			return true
		}
	}
	return false
}

func stripPort(hostport string) string {
	if strings.HasPrefix(hostport, "[") {
		if host, _, err := net.SplitHostPort(hostport); err == nil {
			return host
		}
		return hostport
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

func (e *Evaluator) isAllowlistedCommand(cmd string) bool {
	if len(e.cfg.AllowlistCommands) == 0 {
		return false
	}
	trimmed := strings.TrimSpace(cmd)
	normalized := NormalizeShellCommand(cmd)
	for _, entry := range e.cfg.AllowlistCommands {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == trimmed || entry == normalized {
			return true
		}
	}
	return false
}

func getStringArg(args map[string]any, key string) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	val, ok := args[key]
	if !ok {
		return "", false
	}
	s, ok := val.(string)
	return s, ok
}
