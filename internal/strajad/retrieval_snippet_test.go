package strajad

import (
	"strings"
	"testing"
)

func TestRetrievalQueryTokens_FiltersStopwords(t *testing.T) {
	tokens := retrievalQueryTokens("what is eyesight?")
	if len(tokens) != 1 || tokens[0] != "eyesight" {
		t.Fatalf("expected [eyesight], got %v", tokens)
	}
}

func TestSelectSnippet_PrefersMeaningfulQueryAnchor(t *testing.T) {
	content := strings.Join([]string{
		"4215 0 R (M3 9 72634 21.) 4216 0 R (M3 9 74074 15 4 When the vehicle speed is between approximately 25 MPH and 90 MPH.)",
		"Lane Departure Prevention Function can assist steering under specific conditions.",
		"EyeSight is Subaru's advanced driver assist technology that uses stereo cameras to monitor the road and help reduce collisions.",
	}, " ")
	selection := selectSnippet(content, "what is eyesight?", 180, retrievalConfig{
		maxSnippetChars: 512,
		maxReadCoverage: 0.90,
	})
	if !strings.Contains(strings.ToLower(selection.snippet), "eyesight") {
		t.Fatalf("expected snippet anchored on 'eyesight', got %q", selection.snippet)
	}
}

func TestSanitizeSnippetText_RemovesPDFObjectRefs(t *testing.T) {
	raw := "4215 0 R (M3 9 74074 15 4 When the vehicle speed is between approximately 25 MPH and 90 MPH.) 4217 0 R"
	clean := sanitizeSnippetText(raw)
	if strings.Contains(clean, "0 R") {
		t.Fatalf("expected object refs removed, got %q", clean)
	}
	if !strings.Contains(strings.ToLower(clean), "vehicle speed") {
		t.Fatalf("expected readable phrase preserved, got %q", clean)
	}
}

func TestLooksLikeLowQualityPDFText_DetectsObjectReferenceNoise(t *testing.T) {
	noisy := "4215 0 R 4216 0 R 4217 0 R 4218 0 R 4219 0 R 4220 0 R 4221 0 R 4222 0 R"
	if !looksLikeLowQualityPDFText(noisy) {
		t.Fatalf("expected noisy PDF reference stream to be detected")
	}
	normal := "EyeSight is a driver assist system that helps with pre-collision braking and lane departure warnings."
	if looksLikeLowQualityPDFText(normal) {
		t.Fatalf("expected normal text not to be flagged")
	}
}

func TestScoreSnippetForQuery_PrefersRelevantDefinition(t *testing.T) {
	query := "what is eyesight?"
	relevant := "EyeSight is Subaru's driver assist technology that uses stereo cameras to support safer driving."
	noisy := "Turning off the PreCollision Braking System CharSet /S zero three eight seven one nine four lane departure warning off"
	relevantScore := scoreSnippetForQuery(relevant, query)
	noisyScore := scoreSnippetForQuery(noisy, query)
	if relevantScore <= noisyScore {
		t.Fatalf("expected relevant snippet score > noisy score, got relevant=%.4f noisy=%.4f", relevantScore, noisyScore)
	}
}

func TestScoreSnippetForQuery_DefinitionPatternBoost(t *testing.T) {
	query := "what is eyesight and how does it work?"
	definition := "About EyeSight. EyeSight is a driving support system that uses stereo cameras to assist safer driving."
	mention := "EyeSight OFF indicator and lane departure warning display layout information."

	defScore := scoreSnippetForQuery(definition, query)
	mentionScore := scoreSnippetForQuery(mention, query)
	if defScore <= mentionScore {
		t.Fatalf("expected definition score > mention score, got definition=%.4f mention=%.4f", defScore, mentionScore)
	}
}

func TestJoinSpelledLetterRuns(t *testing.T) {
	in := "Turning off E y e S i g h t now"
	out := joinSpelledLetterRuns(in)
	if !strings.Contains(out, "EyeSight") {
		t.Fatalf("expected EyeSight in output, got %q", out)
	}
}

func TestCleanPDFExtractedText_PreservesMeaningfulSection(t *testing.T) {
	in := strings.Join([]string{
		"stream endobj 250 0 obj << /CS /DeviceCMYK >> endobj",
		"About EyeSight EyeSight is a driving support system that uses a range of functions to assist the driver.",
		"Drivers are responsible for driving safely.",
	}, " ")
	out := cleanPDFExtractedText(in)
	if strings.Contains(strings.ToLower(out), "endobj") {
		t.Fatalf("expected pdf object noise removed, got %q", out)
	}
	if !strings.Contains(strings.ToLower(out), "eyesight is a driving support system") {
		t.Fatalf("expected meaningful eyesight section preserved, got %q", out)
	}
}
