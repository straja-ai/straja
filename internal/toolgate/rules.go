package toolgate

import "regexp"

type rule struct {
	ID              string
	Category        string
	AppliesTo       ToolType
	Action          Action
	DefaultAction   Action
	Pattern         string
	CaseInsensitive bool
	re              *regexp.Regexp
}

// Rule exposes rule definitions for reuse by other guards.
type Rule struct {
	ID              string
	Category        string
	Pattern         string
	CaseInsensitive bool
}

const (
	categoryDataExfil         = "data_exfil"
	categoryUnsafeAction      = "unsafe_action"
	categoryPrivilegeEscalate = "privilege_escalation"
)

func buildRules() []rule {
	defs := ruleDefs()
	out := make([]rule, 0, len(defs))
	for _, d := range defs {
		out = append(out, rule{
			ID:              d.ID,
			Category:        d.Category,
			AppliesTo:       d.AppliesTo,
			Action:          d.Action,
			DefaultAction:   d.DefaultAction,
			Pattern:         d.Pattern,
			CaseInsensitive: d.CaseInsensitive,
		})
	}
	return out
}

func ruleDefs() []rule {
	return []rule{
		{ID: "ordercli_confirm", Category: categoryUnsafeAction, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `\bordercli\b.*–confirm`},
		{ID: "ordercli_pay", Category: categoryUnsafeAction, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `\bordercli\b.*–pay`},
		{ID: "rm_rf_root", Category: categoryUnsafeAction, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `rm\s+-[rR]f\s+/(?:\s|*|$)`},

		{ID: "curl_upload_file", Category: categoryDataExfil, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\bcurl\b[^|;\n]*(?:--upload-file\b|–upload-file\b|-T\b)\s+\S+`, CaseInsensitive: true},
		{ID: "curl_form_file", Category: categoryDataExfil, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\bcurl\b[^|;\n]*\s(?:-F\b|–form\b)\s+\S=@\S+`, CaseInsensitive: true},
		{ID: "curl_data_at_file", Category: categoryDataExfil, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\bcurl\b[^|;\n]*\s(?:-d\b|–data\b|–data-binary\b)\s+@\S+`, CaseInsensitive: true},
		{ID: "wget_post_file", Category: categoryDataExfil, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\bwget\b[^|;\n]*–post-file=\S+`, CaseInsensitive: true},
		{ID: "scp_to_remote", Category: categoryDataExfil, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\bscp\b[^|;\n]*\s+\S+\s+\S+@\S+:\S+`, CaseInsensitive: true},
		{ID: "rsync_to_remote", Category: categoryDataExfil, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\brsync\b[^|;\n]*\s+\S+\s+\S+@\S+:\S+`, CaseInsensitive: true},
		{ID: "sftp_batch_send", Category: categoryDataExfil, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\bsftp\b[^|;\n]*\s+\S+@\S+`, CaseInsensitive: true},
		{ID: "netcat_exfil", Category: categoryDataExfil, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\b(?:nc|ncat|netcat)\b[^;\n]*\s+\S+\s+\d+`, CaseInsensitive: true},
		{ID: "python_requests_post", Category: categoryDataExfil, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\bpython(?:3)?\b[^;\n]*-c\b[^;\n]*\brequests\.post\(`, CaseInsensitive: true},
		{ID: "powershell_invoke_webrequest", Category: categoryDataExfil, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\b(?:powershell|pwsh)\b[^;\n]*\bInvoke-WebRequest\b`, CaseInsensitive: true},

		{ID: "disk_wipe_dd", Category: categoryUnsafeAction, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\bdd\b[^;\n]*\bof=/dev/(?:sd[a-z]\d|nvme\d+n\d+p?\d*|disk\d+)`, CaseInsensitive: true},
		{ID: "mkfs_format", Category: categoryUnsafeAction, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\bmkfs(?:\.\w+)?\b[^;\n]*/dev/(?:sd[a-z]\d|nvme\d+n\d+p?\d*|disk\d+)`, CaseInsensitive: true},
		{ID: "diskutil_erase", Category: categoryUnsafeAction, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\bdiskutil\b[^;\n]*\berase(?:Disk|Volume)\b`, CaseInsensitive: true},
		{ID: "truncate_system_logs", Category: categoryUnsafeAction, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?(?:>\s*/var/log/\S+|\btruncate\b[^;\n]*/var/log/\S+|\brm\b\s+-[rR]f?\s+/var/log/)`, CaseInsensitive: true},
		{ID: "chmod_chown_system_recursive", Category: categoryUnsafeAction, AppliesTo: ToolTypeShell, Action: ActionBlock, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\b(?:chmod|chown)\b[^;\n]*\s+-R\s+(?:/$|/etc/|/usr/|/var/)`, CaseInsensitive: true},

		{ID: "sudo_usage", Category: categoryPrivilegeEscalate, AppliesTo: ToolTypeShell, DefaultAction: ActionWarn, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*\bsudo\b`, CaseInsensitive: true},
		{ID: "cron_persistence", Category: categoryPrivilegeEscalate, AppliesTo: ToolTypeShell, DefaultAction: ActionWarn, Pattern: `(?m)(?:^|[;&|]\s*|\n|\b(?:sudo)\s+)\s*(?:crontab|cron\.d|/etc/cron|at\s+-\w)`, CaseInsensitive: true},
		{ID: "systemd_enable", Category: categoryPrivilegeEscalate, AppliesTo: ToolTypeShell, DefaultAction: ActionWarn, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\bsystemctl\b[^;\n]*\benable\b`, CaseInsensitive: true},
		{ID: "launchctl_persistence", Category: categoryPrivilegeEscalate, AppliesTo: ToolTypeShell, DefaultAction: ActionWarn, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\blaunchctl\b`, CaseInsensitive: true},
		{ID: "user_account_change", Category: categoryPrivilegeEscalate, AppliesTo: ToolTypeShell, DefaultAction: ActionWarn, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\b(?:useradd|adduser|usermod|passwd)\b`, CaseInsensitive: true},
		{ID: "ssh_persistence_modify", Category: categoryPrivilegeEscalate, AppliesTo: ToolTypeShell, DefaultAction: ActionWarn, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\b(?:echo|printf|cat|tee|sed|awk|ed|nano|vi|vim|emacs|cp|mv|install)\b[^;\n]*(?:sshd_config|authorized_keys)\b`, CaseInsensitive: true},
		{ID: "shell_profile_modify", Category: categoryPrivilegeEscalate, AppliesTo: ToolTypeShell, DefaultAction: ActionWarn, Pattern: `(?m)(?:^|[;&|]\s*|\n)\s*(?:\b(?:sudo|doas)\s+)?\b(?:echo|printf|cat|tee|sed|awk|ed|nano|vi|vim|emacs|cp|mv|install)\b[^;\n]*(?:\.bashrc|\.zshrc|\.profile|/etc/profile)\b`, CaseInsensitive: true},
	}
}

// RuleDefs returns shell-oriented rule definitions for reuse (no compiled regex).
func RuleDefs() []Rule {
	defs := ruleDefs()
	out := make([]Rule, 0, len(defs))
	for _, d := range defs {
		if d.AppliesTo != ToolTypeShell {
			continue
		}
		out = append(out, Rule{
			ID:              d.ID,
			Category:        d.Category,
			Pattern:         d.Pattern,
			CaseInsensitive: d.CaseInsensitive,
		})
	}
	return out
}

func compileRules(rules []rule) []rule {
	for i := range rules {
		compiled := compileRuleRegex(rules[i])
		rules[i].re = compiled
	}
	return rules
}

func compileRuleRegex(r rule) *regexp.Regexp {
	pattern := r.Pattern
	if r.CaseInsensitive {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err == nil {
		return re
	}
	pattern = fixPattern(r, pattern)
	re, err = regexp.Compile(pattern)
	if err == nil {
		return re
	}
	return regexp.MustCompile("a^")
}

func fixPattern(r rule, pattern string) string {
	base := r.Pattern
	switch r.ID {
	case "rm_rf_root":
		base = `rm\s+-[rR]f\s+/(?:\s|\*|$)`
	case "python_requests_post":
		base = `\bpython(?:3)?\b[^;\n]-c\b[^;\n]\brequests\.post\(`
	default:
		base = regexp.QuoteMeta(r.Pattern)
	}
	if r.CaseInsensitive {
		return "(?i)" + base
	}
	return base
}
