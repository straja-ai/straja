package toolgate

import (
	"context"
	"testing"

	"github.com/straja-ai/straja/internal/config"
)

type fakeRunner struct {
	called bool
}

func (r *fakeRunner) Run(ctx context.Context, call ToolCall) (any, error) {
	r.called = true
	return "ok", nil
}

type fakeEmitter struct {
	hits []Hit
}

func (e *fakeEmitter) EmitToolGateHit(ctx context.Context, hit Hit) {
	e.hits = append(e.hits, hit)
}

func TestExecutorBlocksWithToolPolicyError(t *testing.T) {
	runner := &fakeRunner{}
	eval := New(config.ToolGateConfig{Enabled: true, Mode: string(ModeElevatedOnly)})
	exec := &Executor{Gate: eval, Runner: runner}

	_, res, err := exec.Execute(context.Background(), ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "rm -rf /"}})
	if err == nil {
		t.Fatalf("expected tool policy error")
	}
	if runner.called {
		t.Fatalf("runner should not be called on block")
	}
	if res.Action != ActionBlock {
		t.Fatalf("expected block action, got %s", res.Action)
	}
	policyErr, ok := err.(*ToolPolicyError)
	if !ok {
		t.Fatalf("expected ToolPolicyError, got %T", err)
	}
	if policyErr.Type != "straja_tool_policy_violation" || policyErr.Code != "tool_blocked" {
		t.Fatalf("unexpected error fields: type=%s code=%s", policyErr.Type, policyErr.Code)
	}
	if policyErr.RuleID != "rm_rf_root" || policyErr.Category != categoryUnsafeAction {
		t.Fatalf("unexpected rule info: rule=%s category=%s", policyErr.RuleID, policyErr.Category)
	}
}

func TestExecutorWarnsAndEmitsHit(t *testing.T) {
	runner := &fakeRunner{}
	emitter := &fakeEmitter{}
	eval := New(config.ToolGateConfig{Enabled: true, Mode: string(ModeAllTools)})
	exec := &Executor{Gate: eval, Runner: runner, Emitter: emitter}

	_, res, err := exec.Execute(context.Background(), ToolCall{Type: ToolTypeShell, Args: map[string]any{"command": "sudo ls"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ActionWarn {
		t.Fatalf("expected warn action, got %s", res.Action)
	}
	if !runner.called {
		t.Fatalf("runner should be called on warn")
	}
	if len(emitter.hits) == 0 {
		t.Fatalf("expected emitted hit")
	}
	if !hasRule(emitter.hits, "sudo_usage") {
		t.Fatalf("expected sudo_usage hit")
	}
	for _, hit := range emitter.hits {
		if hit.Confidence != 1 {
			t.Fatalf("expected confidence=1, got %v", hit.Confidence)
		}
		if len(hit.Sources) != 2 {
			t.Fatalf("expected sources, got %v", hit.Sources)
		}
		if len(hit.Evidence) == 0 || len(hit.Evidence) > 120 {
			t.Fatalf("unexpected evidence length %d", len(hit.Evidence))
		}
	}
}

func TestNodesRunPathEvaluatesToolGate(t *testing.T) {
	runner := &fakeRunner{}
	eval := New(config.ToolGateConfig{Enabled: true, Mode: string(ModeElevatedOnly)})
	exec := &Executor{Gate: eval, Runner: runner}

	_, _, err := exec.Execute(context.Background(), ToolCall{Name: "nodes.run", Type: ToolTypeShell, Args: map[string]any{"command": "rm -rf /"}})
	if err == nil {
		t.Fatalf("expected tool policy error")
	}
	if runner.called {
		t.Fatalf("runner should not be called for nodes.run block")
	}
}
