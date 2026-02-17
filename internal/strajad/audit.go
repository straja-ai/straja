package strajad

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type auditDecision string

const (
	auditDecisionAllow auditDecision = "allow"
	auditDecisionDeny  auditDecision = "deny"
)

// AuditEvent captures an immutable access decision for traceability.
type AuditEvent struct {
	Timestamp  time.Time      `json:"timestamp"`
	RequestID  string         `json:"request_id"`
	RemoteAddr string         `json:"remote_addr,omitempty"`
	RPCMethod  string         `json:"rpc_method,omitempty"`
	Tool       string         `json:"tool,omitempty"`
	Decision   auditDecision  `json:"decision"`
	Reason     string         `json:"reason"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// Auditor stores audit events in-memory and optionally appends JSONL to disk.
type Auditor struct {
	mu          sync.RWMutex
	events      []AuditEvent
	maxInMemory int

	file   *os.File
	writer *bufio.Writer
}

func newAuditor(path string, maxInMemory int) (*Auditor, error) {
	if maxInMemory <= 0 {
		maxInMemory = 2000
	}
	a := &Auditor{maxInMemory: maxInMemory}

	if path == "" {
		return a, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	a.file = f
	a.writer = bufio.NewWriter(f)
	return a, nil
}

func (a *Auditor) Record(_ context.Context, ev AuditEvent) {
	if a == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.events = append(a.events, ev)
	if len(a.events) > a.maxInMemory {
		a.events = append([]AuditEvent(nil), a.events[len(a.events)-a.maxInMemory:]...)
	}

	if a.writer != nil {
		data, err := json.Marshal(ev)
		if err == nil {
			_, _ = a.writer.Write(data)
			_ = a.writer.WriteByte('\n')
			_ = a.writer.Flush()
		}
	}
}

func (a *Auditor) List(limit int) []AuditEvent {
	if a == nil {
		return nil
	}
	if limit <= 0 {
		limit = 20
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.events) == 0 {
		return []AuditEvent{}
	}
	if limit > len(a.events) {
		limit = len(a.events)
	}

	out := make([]AuditEvent, 0, limit)
	for i := len(a.events) - 1; i >= len(a.events)-limit; i-- {
		out = append(out, a.events[i])
	}
	return out
}

func (a *Auditor) Close(_ context.Context) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.writer != nil {
		_ = a.writer.Flush()
	}
	if a.file != nil {
		return a.file.Close()
	}
	return nil
}
