package strajaguard

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Integration test: runs real ONNX models from a locally cached bundle.
//
// This is opt-in because it depends on the presence of bundle artifacts and ONNX Runtime.
func TestIntegration_SpecialistsDetectionsPresent(t *testing.T) {
	if os.Getenv("STRAJA_INTEGRATION") == "" {
		t.Skip("set STRAJA_INTEGRATION=1 to run integration tests")
	}

	root := filepath.Join("intel", "strajaguard_v1_specialists")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir %s: %v", root, err)
	}
	var versions []string
	for _, e := range entries {
		if e.IsDir() {
			versions = append(versions, e.Name())
		}
	}
	if len(versions) == 0 {
		t.Fatalf("no cached bundle versions under %s", root)
	}
	sort.Strings(versions)
	bundleDir := filepath.Join(root, versions[len(versions)-1])

	rt := ResolveRuntime(RuntimeConfig{MaxSessions: 1, IntraThreads: 1, InterThreads: 1})
	engine, _, err := LoadSpecialistsEngine(bundleDir, 256, rt, "configs/strajaguard_specialists.yaml")
	if err != nil {
		t.Fatalf("LoadSpecialistsEngine: %v", err)
	}

	res, err := engine.AnalyzeText(WithRequestID(context.Background(), "it"), "how are you?")
	if err != nil {
		t.Fatalf("AnalyzeText: %v", err)
	}
	t.Logf("scores=%v", res.Scores)
	if res == nil || res.Detections == nil {
		t.Fatalf("expected detections to be non-nil")
	}
	if res.Detections.Jailbreak == nil {
		t.Fatalf("expected jailbreak detections to be present")
	}
	if res.Detections.PromptInjection == nil {
		t.Fatalf("expected prompt_injection detections to be present")
	}
	t.Logf("jailbreak ensemble=%+v detectors=%+v", res.Detections.Jailbreak.Ensemble, res.Detections.Jailbreak.Detectors)
	t.Logf("prompt_injection ensemble=%+v detectors=%+v", res.Detections.PromptInjection.Ensemble, res.Detections.PromptInjection.Detectors)
}
