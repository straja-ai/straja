package strajaguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrBundleStateNotFound is returned when state.json is missing.
var ErrBundleStateNotFound = errors.New("strajaguard bundle state not found")

// BundleState tracks the active and previous bundle versions.
type BundleState struct {
	CurrentVersion  string `json:"current_version"`
	PreviousVersion string `json:"previous_version,omitempty"`
}

func stateFilePath(baseDir string) string {
	return filepath.Join(baseDir, "state.json")
}

// LoadBundleState reads <intel_dir>/<family>/state.json.
func LoadBundleState(baseDir string) (BundleState, error) {
	baseDir = strings.TrimSpace(baseDir)
	if baseDir == "" {
		return BundleState{}, errors.New("baseDir is empty")
	}

	data, err := os.ReadFile(stateFilePath(baseDir))
	if err != nil {
		if os.IsNotExist(err) {
			return BundleState{}, ErrBundleStateNotFound
		}
		return BundleState{}, fmt.Errorf("read bundle state: %w", err)
	}

	var state BundleState
	if err := json.Unmarshal(data, &state); err != nil {
		return BundleState{}, fmt.Errorf("decode bundle state: %w", err)
	}
	return state, nil
}

// SaveBundleState writes <intel_dir>/<family>/state.json atomically.
func SaveBundleState(baseDir string, state BundleState) error {
	baseDir = strings.TrimSpace(baseDir)
	if baseDir == "" {
		return errors.New("baseDir is empty")
	}

	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return fmt.Errorf("create bundle base dir: %w", err)
	}

	state.CurrentVersion = strings.TrimSpace(state.CurrentVersion)
	state.PreviousVersion = strings.TrimSpace(state.PreviousVersion)

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode bundle state: %w", err)
	}

	tmpFile, err := os.CreateTemp(baseDir, "state.json.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp state file: %w", err)
	}
	if err := tmpFile.Chmod(0o644); err != nil {
		tmpFile.Close()
		return fmt.Errorf("chmod temp state file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp state file: %w", err)
	}

	if err := os.Rename(tmpFile.Name(), stateFilePath(baseDir)); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	return nil
}
