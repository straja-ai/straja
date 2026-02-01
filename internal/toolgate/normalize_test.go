package toolgate

import (
	"testing"

	"github.com/straja-ai/straja/internal/config"
)

func TestNormalizationCatchesBypass(t *testing.T) {
	eval := New(config.ToolGateConfig{Enabled: true, Mode: string(ModeElevatedOnly)})
	cases := []string{
		`r\m -rf /`,
		`rm -r${IFS}f /`,
	}
	for _, cmd := range cases {
		res := eval.Evaluate(ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": cmd}})
		if res.Action != ActionBlock {
			t.Fatalf("expected block for %q, got %s", cmd, res.Action)
		}
		if !hasRule(res.Hits, "rm_rf_root") {
			t.Fatalf("expected rm_rf_root hit for %q", cmd)
		}
	}
}
