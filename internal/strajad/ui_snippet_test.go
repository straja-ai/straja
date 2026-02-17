package strajad

import "testing"

func TestPrioritizeSnippetsForTask_FiltersLowRelevanceNoise(t *testing.T) {
	task := "what is eyesight and how does it work?"
	in := []snippetHit{
		{
			ID:         "noise",
			Collection: "work",
			Snippet:    "stream endobj 250 0 obj << /CS /DeviceCMYK /S /Transparency >>",
		},
		{
			ID:         "good",
			Collection: "work",
			Snippet:    "EyeSight is a driving support system that uses stereo cameras to assist safer driving.",
		},
		{
			ID:         "weak",
			Collection: "work",
			Snippet:    "Instrument panel display layout and warning indicator details.",
		},
	}
	out := prioritizeSnippetsForTask(task, in, 3)
	if len(out) == 0 {
		t.Fatalf("expected prioritized snippets")
	}
	if out[0].ID != "good" {
		t.Fatalf("expected relevant snippet first, got %q", out[0].ID)
	}
	for _, hit := range out {
		if hit.ID == "noise" {
			t.Fatalf("expected low-relevance noise snippet to be filtered")
		}
	}
}
