package server

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/straja-ai/straja/internal/config"
)

const maxConsoleConfigBytes = 5 * 1024 * 1024

func (s *Server) handleConsoleConfig(w http.ResponseWriter, r *http.Request) {
	setConsoleRobotsHeader(w)

	if s == nil || strings.TrimSpace(s.configPath) == "" {
		http.Error(w, "config path not set", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(s.configPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.Error(w, "config file not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to read config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/yaml")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
		return
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxConsoleConfigBytes)
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if len(strings.TrimSpace(string(payload))) == 0 {
			http.Error(w, "config body is empty", http.StatusBadRequest)
			return
		}
		if err := validateConfigPayload(payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := writeFileAtomic(s.configPath, payload, 0o644); err != nil {
			http.Error(w, "failed to write config", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func (s *Server) handleConsoleReload(w http.ResponseWriter, r *http.Request) {
	setConsoleRobotsHeader(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte("reload not supported; restart gateway"))
}

func validateConfigPayload(payload []byte) error {
	dir := os.TempDir()
	tmp, err := os.CreateTemp(dir, "straja-config-*.yaml")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	defer os.Remove(name)

	cfg, err := config.Load(name)
	if err != nil {
		return err
	}
	if err := config.Validate(cfg); err != nil {
		return err
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".straja-config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
