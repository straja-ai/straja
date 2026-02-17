package strajad

import (
	"strings"
	"testing"
)

func TestExtractTextFromPDFHeuristic_RecoversReadablePhrases(t *testing.T) {
	raw := `%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
/Names [(M3.9.81567.32.When.the.EyeSight.temporary.stop.indicator.has.illuminated.no.EyeSight) 4222 0 R]
/Title (subarucaution.eps)
/Length 21635
stream
/9j/4AAQSkZJRgABAgEASABIAAD4AAQSkZJRgABAgEA
endstream
%%EOF`

	text, truncated := extractTextFromPDFHeuristic([]byte(raw), 2000)
	if truncated {
		t.Fatalf("expected non-truncated extract")
	}
	if strings.TrimSpace(text) == "" {
		t.Fatalf("expected non-empty extracted text")
	}
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "eyesight temporary stop indicator has illuminated") {
		t.Fatalf("expected readable Eyesight phrase, got %q", text)
	}
	if strings.Contains(lower, "%pdf-1.4") {
		t.Fatalf("expected PDF header to be filtered, got %q", text)
	}
}

func TestNormalizePDFCandidate_FiltersMetadataAndBase64(t *testing.T) {
	if got := normalizePDFCandidate("%PDF-1.4"); got != "" {
		t.Fatalf("expected PDF header candidate to be dropped, got %q", got)
	}
	if got := normalizePDFCandidate("/9j/4AAQSkZJRgABAgEASABIAAD4AAQSkZJRgABAgEA"); got != "" {
		t.Fatalf("expected base64-like candidate to be dropped, got %q", got)
	}
	if got := normalizePDFCandidate("When.the.EyeSight.temporary.stop.indicator.has.illuminated"); got == "" {
		t.Fatalf("expected readable candidate to survive normalization")
	}
}
