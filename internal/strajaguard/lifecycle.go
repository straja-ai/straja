package strajaguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/redact"
)

func bundleDirLooksValid(dir, family string) bool {
	required := []string{
		"manifest.json",
		"manifest.sig",
	}
	for _, p := range required {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			return false
		}
	}

	switch normalizeBundleFamily(family) {
	case "strajaguard_v1_specialists":
		for _, name := range []string{"prompt_injection", "jailbreak", "pii_ner"} {
			if !specialistDirLooksValid(filepath.Join(dir, name)) {
				return false
			}
		}
	default:
		required = []string{
			"strajaguard_v1.onnx",
			"label_map.json",
			"thresholds.yaml",
			filepath.Join("tokenizer", "vocab.txt"),
		}
		for _, p := range required {
			if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
				return false
			}
		}
	}
	return true
}

func specialistDirLooksValid(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "model.int8.onnx")); err != nil {
		if _, err := os.Stat(filepath.Join(dir, "model.onnx")); err != nil {
			return false
		}
	}
	if !tokenizerAssetsPresent(dir) {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil && !os.IsNotExist(err) {
		return false
	}
	return true
}

func tokenizerAssetsPresent(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "vocab.txt")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "tokenizer", "vocab.txt")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "tokenizer.json")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "tokenizer", "tokenizer.json")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "tokenizer")); err == nil {
		return true
	}
	return false
}

// EnsureStrajaGuardVersion downloads, verifies, and activates a version under baseDir/version.
func EnsureStrajaGuardVersion(ctx context.Context, baseDir, family, version, manifestURL, signatureURL, fileBaseURL, token string, timeoutSeconds int) (string, error) {
	baseDir = strings.TrimSpace(baseDir)
	version = strings.TrimSpace(version)
	family = normalizeBundleFamily(family)
	if baseDir == "" {
		return "", errors.New("baseDir is empty")
	}
	if version == "" {
		return "", errors.New("version is empty")
	}
	if token = strings.TrimSpace(token); token == "" {
		return "", errors.New("bundle token is empty")
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}

	if ctx == nil {
		ctx = context.Background()
	}
	timeout := time.Duration(timeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	finalDir := filepath.Join(baseDir, version)
	if bundleDirLooksValid(finalDir, family) {
		return finalDir, nil
	}

	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return "", fmt.Errorf("create bundle base dir: %w", err)
	}

	tmpDir, err := os.MkdirTemp(baseDir, version+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}

	success := false
	defer func() {
		if !success {
			os.RemoveAll(tmpDir)
		}
	}()

	redact.Logf("strajaguard: downloading bundle version=%s", version)

	client := &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second}
	pk, err := manifestPublicKey()
	if err != nil {
		return "", fmt.Errorf("load manifest public key: %w", err)
	}

	manifestBytes, manifest, err := downloadManifest(ctx, client, strings.TrimSpace(manifestURL), token)
	if err != nil {
		return "", err
	}

	sigEncoded, sigAlgorithm, sigRawBytes, err := downloadSignature(ctx, client, strings.TrimSpace(signatureURL), token)
	if err != nil {
		return "", err
	}

	if err := verifyManifest(manifestBytes, manifest.Version, sigEncoded, sigAlgorithm, pk); err != nil {
		return "", err
	}

	if manifest.Version != version {
		return "", fmt.Errorf("manifest version mismatch: expected %s, got %s", version, manifest.Version)
	}

	if err := downloadBundleFiles(ctx, client, tmpDir, manifest.Files, strings.TrimSpace(fileBaseURL), token); err != nil {
		return "", err
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "manifest.json"), manifestBytes, 0o644); err != nil {
		return "", fmt.Errorf("write manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "manifest.sig"), sigRawBytes, 0o644); err != nil {
		return "", fmt.Errorf("write manifest signature: %w", err)
	}

	backupDir := finalDir + ".bak"
	if _, err := os.Stat(finalDir); err == nil {
		_ = os.RemoveAll(backupDir)
		if err := os.Rename(finalDir, backupDir); err != nil {
			return "", fmt.Errorf("prepare existing bundle for replacement: %w", err)
		}
	}

	if err := os.Rename(tmpDir, finalDir); err != nil {
		if _, statErr := os.Stat(backupDir); statErr == nil {
			_ = os.Rename(backupDir, finalDir)
		}
		return "", fmt.Errorf("activate bundle: %w", err)
	}

	_ = os.RemoveAll(backupDir)
	success = true
	return finalDir, nil
}

// DecideFallback determines how to handle a failed bundle update/install.
// It is pure so it can be tested without ONNX/runtime dependencies.
func DecideFallback(currentVersion string, requireML, allowRegexOnly bool, verifyErr error) (keepVersion string, fallbackMode string, err error) {
	if verifyErr == nil {
		return currentVersion, "ml", nil
	}
	if strings.TrimSpace(currentVersion) != "" {
		// Keep existing bundle if one is active.
		return currentVersion, "ml", nil
	}

	if allowRegexOnly {
		return "", "regex_only", nil
	}
	if requireML {
		return "", "", fmt.Errorf("bundle verification failed and no previous bundle; require_ml=true so cannot continue")
	}
	return "", "disabled_ml", nil
}
