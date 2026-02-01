package toolgate

import "strings"

type ExplainHit struct {
	RuleID       string
	Category     string
	Action       string
	MatchedOn    string
	EvidenceSpan [2]int
}

type ExplainResult struct {
	Hits                []ExplainHit
	Normalized          string
	NormalizedAvailable bool
}

// Explain evaluates a tool call and returns matched-on metadata without exposing regex patterns.
func (e *Evaluator) Explain(call ToolCall) (Result, ExplainResult) {
	res := e.Evaluate(call)
	explain := ExplainResult{}
	if call.Type == "" {
		call.Type = inferToolType(call)
	}

	if call.Type == ToolTypeShell {
		cmd := extractShellCommand(call)
		if strings.TrimSpace(cmd) != "" {
			explain.Normalized = NormalizeShellCommand(cmd)
			explain.NormalizedAvailable = true
		}
		explain.Hits = append(explain.Hits, e.explainShellHits(call, res)...)
		return res, explain
	}
	if call.Type == ToolTypeFilesystem {
		explain.Hits = append(explain.Hits, e.explainFilesystemHits(call, res)...)
		return res, explain
	}
	if call.Type == ToolTypeHTTP {
		explain.Hits = append(explain.Hits, e.explainHTTPHits(call, res)...)
		return res, explain
	}
	return res, explain
}

func (e *Evaluator) explainShellHits(call ToolCall, res Result) []ExplainHit {
	if len(res.Hits) == 0 {
		return nil
	}
	cmd := extractShellCommand(call)
	normalized := NormalizeShellCommand(cmd)
	byID := map[string]Hit{}
	for _, h := range res.Hits {
		byID[h.RuleID] = h
	}

	var out []ExplainHit
	for _, r := range e.rules {
		if r.AppliesTo != ToolTypeShell {
			continue
		}
		hit, ok := byID[r.ID]
		if !ok {
			continue
		}
		matchedOn := ""
		span := [2]int{-1, -1}
		if r.re != nil {
			if loc := r.re.FindStringIndex(cmd); loc != nil {
				matchedOn = "original"
				span = [2]int{loc[0], loc[1]}
			} else if loc := r.re.FindStringIndex(normalized); loc != nil {
				matchedOn = "normalized"
				span = [2]int{loc[0], loc[1]}
			}
		}
		out = append(out, ExplainHit{
			RuleID:       hit.RuleID,
			Category:     hit.Category,
			Action:       hit.Action,
			MatchedOn:    matchedOn,
			EvidenceSpan: span,
		})
	}

	if hit, ok := byID["read_sensitive_files"]; ok {
		matchedOn := ""
		span := [2]int{-1, -1}
		if e.sensitivePaths != nil && e.sensitivePaths.re != nil {
			if loc := e.sensitivePaths.re.FindStringIndex(cmd); loc != nil {
				matchedOn = "original"
				span = [2]int{loc[0], loc[1]}
			} else if loc := e.sensitivePaths.re.FindStringIndex(normalized); loc != nil {
				matchedOn = "normalized"
				span = [2]int{loc[0], loc[1]}
			}
		}
		out = append(out, ExplainHit{
			RuleID:       hit.RuleID,
			Category:     hit.Category,
			Action:       hit.Action,
			MatchedOn:    matchedOn,
			EvidenceSpan: span,
		})
	}

	return out
}

func (e *Evaluator) explainFilesystemHits(call ToolCall, res Result) []ExplainHit {
	if len(res.Hits) == 0 {
		return nil
	}
	byID := map[string]Hit{}
	for _, h := range res.Hits {
		byID[h.RuleID] = h
	}
	if hit, ok := byID["read_sensitive_files"]; ok {
		paths := extractPaths(call.Args)
		matchedOn := "original"
		span := [2]int{-1, -1}
		for _, p := range paths {
			if e.sensitivePaths != nil && e.sensitivePaths.re != nil {
				if loc := e.sensitivePaths.re.FindStringIndex(p); loc != nil {
					span = [2]int{loc[0], loc[1]}
					break
				}
			}
		}
		return []ExplainHit{{
			RuleID:       hit.RuleID,
			Category:     hit.Category,
			Action:       hit.Action,
			MatchedOn:    matchedOn,
			EvidenceSpan: span,
		}}
	}
	return nil
}

func (e *Evaluator) explainHTTPHits(call ToolCall, res Result) []ExplainHit {
	if len(res.Hits) == 0 {
		return nil
	}
	out := make([]ExplainHit, 0, len(res.Hits))
	for _, hit := range res.Hits {
		span := [2]int{-1, -1}
		if hit.Evidence != "" {
			span = [2]int{0, len(hit.Evidence)}
		}
		out = append(out, ExplainHit{
			RuleID:       hit.RuleID,
			Category:     hit.Category,
			Action:       hit.Action,
			MatchedOn:    "original",
			EvidenceSpan: span,
		})
	}
	return out
}
