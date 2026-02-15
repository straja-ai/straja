package updater

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAssetName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		goos   string
		goarch string
		want   string
	}{
		{goos: "linux", goarch: "amd64", want: "straja_linux_amd64.tar.gz"},
		{goos: "darwin", goarch: "arm64", want: "straja_darwin_arm64.tar.gz"},
		{goos: "windows", goarch: "amd64", want: "straja_windows_amd64.zip"},
	}
	for _, tc := range tests {
		got, err := AssetName(tc.goos, tc.goarch)
		if err != nil {
			t.Fatalf("AssetName(%s,%s) error: %v", tc.goos, tc.goarch, err)
		}
		if got != tc.want {
			t.Fatalf("AssetName(%s,%s) = %q, want %q", tc.goos, tc.goarch, got, tc.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	t.Parallel()
	if available, comparable := compareVersions("v0.1.0", "v0.2.0"); !comparable || !available {
		t.Fatalf("expected update available=true comparable=true, got available=%t comparable=%t", available, comparable)
	}
	if available, comparable := compareVersions("v0.2.0", "v0.2.0"); !comparable || available {
		t.Fatalf("expected update available=false comparable=true, got available=%t comparable=%t", available, comparable)
	}
	if _, comparable := compareVersions("dev", "v0.2.0"); comparable {
		t.Fatal("expected non-comparable dev version")
	}
}

func TestParseChecksums(t *testing.T) {
	t.Parallel()
	content := strings.Join([]string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  straja_linux_amd64.tar.gz",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb *straja_windows_amd64.zip",
	}, "\n")
	got := parseChecksums(content)
	if got["straja_linux_amd64.tar.gz"] != strings.Repeat("a", 64) {
		t.Fatalf("unexpected checksum for linux asset: %q", got["straja_linux_amd64.tar.gz"])
	}
	if got["straja_windows_amd64.zip"] != strings.Repeat("b", 64) {
		t.Fatalf("unexpected checksum for windows asset: %q", got["straja_windows_amd64.zip"])
	}
}

func TestApplyPackagePreservesConfig(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	src := filepath.Join(root, "src")
	dst := filepath.Join(root, "dst")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "straja"), []byte("new-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "straja.yaml"), []byte("new-config"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "straja"), []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "straja.yaml"), []byte("current-config"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := applyPackage(src, dst, true); err != nil {
		t.Fatalf("applyPackage error: %v", err)
	}

	bin, err := os.ReadFile(filepath.Join(dst, "straja"))
	if err != nil {
		t.Fatal(err)
	}
	if string(bin) != "new-binary" {
		t.Fatalf("binary was not updated: %q", string(bin))
	}
	cfg, err := os.ReadFile(filepath.Join(dst, "straja.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg) != "current-config" {
		t.Fatalf("config should be preserved, got %q", string(cfg))
	}
}

func TestExtractTarGzRejectsTraversal(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	archivePath := filepath.Join(root, "bad.tar.gz")
	if err := writeTestTarGz(archivePath, "../evil.txt", "boom"); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "stage")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := extractTarGz(archivePath, stage); err == nil {
		t.Fatal("expected traversal error")
	}
}

func writeTestTarGz(path, entryName, content string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	hdr := &tar.Header{
		Name: entryName,
		Mode: 0o644,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = tw.Write([]byte(content))
	return err
}
