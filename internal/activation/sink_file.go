package activation

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileSink appends activation events to a JSONL file.
type FileSink struct {
	path   string
	file   *os.File
	writer *bufio.Writer
	mu     sync.Mutex
}

func NewFileSink(path string) (*FileSink, error) {
	if path == "" {
		return nil, fmt.Errorf("file path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("create dirs: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	return &FileSink{
		path:   path,
		file:   f,
		writer: bufio.NewWriter(f),
	}, nil
}

func (s *FileSink) Name() string { return "file_jsonl:" + s.path }

func (s *FileSink) Deliver(_ context.Context, ev *Event) error {
	if ev == nil {
		return nil
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.writer.Write(data); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	if err := s.writer.WriteByte('\n'); err != nil {
		return fmt.Errorf("write newline: %w", err)
	}
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	return nil
}

func (s *FileSink) Close(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writer != nil {
		_ = s.writer.Flush()
	}
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}
