package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLocalBundleVersionUsesCurrentWhenPresent(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "20260101-000000"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "20260101-000000", "manifest.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	got, err := resolveLocalBundleVersion(tmp, "20260101-000000")
	if err != nil {
		t.Fatalf("resolveLocalBundleVersion returned error: %v", err)
	}
	if got != "20260101-000000" {
		t.Fatalf("expected current version, got %q", got)
	}
}

func TestResolveLocalBundleVersionFindsLatestManifestDir(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	for _, ver := range []string{"20260101-000000", "20260102-000000"} {
		if err := os.MkdirAll(filepath.Join(tmp, ver), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", ver, err)
		}
		if err := os.WriteFile(filepath.Join(tmp, ver, "manifest.json"), []byte("{}"), 0o644); err != nil {
			t.Fatalf("write manifest %s: %v", ver, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(tmp, "20260103-000000.tmp-123"), 0o755); err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}

	got, err := resolveLocalBundleVersion(tmp, "")
	if err != nil {
		t.Fatalf("resolveLocalBundleVersion returned error: %v", err)
	}
	if got != "20260102-000000" {
		t.Fatalf("expected latest version, got %q", got)
	}
}

func TestResolveLocalBundleVersionSupportsFlatBundleRoot(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), []byte(`{"version":"20260212-184714"}`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "manifest.sig"), []byte("sig"), 0o644); err != nil {
		t.Fatalf("write manifest sig: %v", err)
	}
	got, err := resolveLocalBundleVersion(tmp, "")
	if err != nil {
		t.Fatalf("resolveLocalBundleVersion returned error: %v", err)
	}
	if got != "." {
		t.Fatalf("expected flat bundle marker '.', got %q", got)
	}
}
