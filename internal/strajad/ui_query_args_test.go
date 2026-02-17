package strajad

import "testing"

func TestQueryReadArgsFromPlan_EnforcesUIFloor(t *testing.T) {
	plan := deterministicPlan{
		RecommendedToolCalls: []recommendedCall{
			{
				Name: "vault.read_snippets",
				Args: map[string]any{
					"max_bytes":             1024,
					"max_chars_per_snippet": 256,
				},
			},
		},
	}

	args := queryReadArgsFromPlan(plan, "what is eyesight?", []string{"note_1::chunk_1"}, 4096, 512)
	maxBytes, _ := args["max_bytes"].(int)
	maxChars, _ := args["max_chars_per_snippet"].(int)

	if maxBytes != 2048 {
		t.Fatalf("expected UI floor max_bytes=2048, got %d", maxBytes)
	}
	if maxChars != 420 {
		t.Fatalf("expected UI floor max_chars_per_snippet=420, got %d", maxChars)
	}
}

func TestQueryReadArgsFromPlan_RespectsMaxBudget(t *testing.T) {
	plan := deterministicPlan{
		RecommendedToolCalls: []recommendedCall{
			{
				Name: "vault.read_snippets",
				Args: map[string]any{
					"max_bytes":             999999,
					"max_chars_per_snippet": 999999,
				},
			},
		},
	}

	args := queryReadArgsFromPlan(plan, "what is eyesight?", []string{"note_1::chunk_1"}, 4096, 512)
	maxBytes, _ := args["max_bytes"].(int)
	maxChars, _ := args["max_chars_per_snippet"].(int)

	if maxBytes != 4096 {
		t.Fatalf("expected max_bytes clamped to budget 4096, got %d", maxBytes)
	}
	if maxChars != 512 {
		t.Fatalf("expected max_chars_per_snippet clamped to budget 512, got %d", maxChars)
	}
}
