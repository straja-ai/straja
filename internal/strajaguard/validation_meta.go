package strajaguard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidationMeta tracks when a bundle version was last validated online.
type ValidationMeta struct {
	Version            string `json:"version"`
	LastValidatedAt    string `json:"last_validated_at"`
	LicenseFingerprint string `json:"license_fingerprint,omitempty"`
	Source             string `json:"source,omitempty"`
}

func validationMetaPath(baseDir string) string {
	return filepath.Join(baseDir, "validation_meta.json")
}

// SaveValidationMeta writes validation metadata (non-secret).
func SaveValidationMeta(baseDir string, meta ValidationMeta) error {
	baseDir = strings.TrimSpace(baseDir)
	if baseDir == "" {
		return fmt.Errorf("baseDir is empty")
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return fmt.Errorf("create base dir: %w", err)
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("encode validation meta: %w", err)
	}
	tmp, err := os.CreateTemp(baseDir, "validation_meta.json.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp validation meta: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp validation meta: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp validation meta: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp validation meta: %w", err)
	}
	if err := os.Rename(tmp.Name(), validationMetaPath(baseDir)); err != nil {
		return fmt.Errorf("replace validation meta: %w", err)
	}
	return nil
}

// LoadValidationMeta reads validation metadata if present.
func LoadValidationMeta(baseDir string) (ValidationMeta, error) {
	baseDir = strings.TrimSpace(baseDir)
	if baseDir == "" {
		return ValidationMeta{}, fmt.Errorf("baseDir is empty")
	}
	data, err := os.ReadFile(validationMetaPath(baseDir))
	if err != nil {
		return ValidationMeta{}, err
	}
	var meta ValidationMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return ValidationMeta{}, fmt.Errorf("decode validation meta: %w", err)
	}
	return meta, nil
}
