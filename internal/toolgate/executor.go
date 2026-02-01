package toolgate

import (
	"context"
	"fmt"
)

type Runner interface {
	Run(ctx context.Context, call ToolCall) (any, error)
}

type HitEmitter interface {
	EmitToolGateHit(ctx context.Context, hit Hit)
}

// Executor enforces tool-gate decisions before running tools.
type Executor struct {
	Gate    *Evaluator
	Runner  Runner
	Emitter HitEmitter
}

func (e *Executor) Execute(ctx context.Context, call ToolCall) (any, Result, error) {
	if e.Gate == nil {
		return nil, Result{Action: ActionAllow}, fmt.Errorf("toolgate: missing evaluator")
	}
	res := e.Gate.Evaluate(call)
	for _, hit := range res.Hits {
		if e.Emitter != nil {
			e.Emitter.EmitToolGateHit(ctx, hit)
		}
	}
	if res.Action == ActionBlock {
		return nil, res, newToolPolicyError(res)
	}
	if e.Runner == nil {
		return nil, res, nil
	}
	out, err := e.Runner.Run(ctx, call)
	return out, res, err
}

// ToolPolicyError is an OpenAI-compatible tool policy violation.
type ToolPolicyError struct {
	Type     string
	Code     string
	RuleID   string
	Category string
}

func (e *ToolPolicyError) Error() string {
	return fmt.Sprintf("tool blocked by policy rule_id=%s category=%s", e.RuleID, e.Category)
}

func newToolPolicyError(res Result) error {
	primary := pickPrimaryHit(res.Hits)
	return &ToolPolicyError{
		Type:     "straja_tool_policy_violation",
		Code:     "tool_blocked",
		RuleID:   primary.RuleID,
		Category: primary.Category,
	}
}

func pickPrimaryHit(hits []Hit) Hit {
	for _, hit := range hits {
		if hit.Action == string(ActionBlock) {
			return hit
		}
	}
	if len(hits) > 0 {
		return hits[0]
	}
	return Hit{}
}
