package strajad

import (
	"strings"
	"time"
)

type readWindowUsage struct {
	WindowID  string
	BytesUsed int
	ExpiresAt time.Time
}

func (d *Daemon) enforceReadRate(tool string) *rpcError {
	if d == nil {
		return nil
	}
	tool = strings.TrimSpace(tool)
	if tool == "" {
		tool = "read"
	}
	limit := d.cfg.MaxReadRPM
	if limit <= 0 {
		limit = 30
	}
	now := time.Now().UTC()
	cutoff := now.Add(-1 * time.Minute)

	d.readMu.Lock()
	defer d.readMu.Unlock()

	globalFiltered := filterRecentTimes(d.readRates["all_reads"], cutoff)
	if len(globalFiltered) >= limit {
		d.readRates["all_reads"] = append([]time.Time(nil), globalFiltered...)
		return budgetErr("read_rate_limit_exceeded", "max_read_rpm", limit)
	}
	toolFiltered := filterRecentTimes(d.readRates[tool], cutoff)
	if len(toolFiltered) >= limit {
		d.readRates[tool] = append([]time.Time(nil), toolFiltered...)
		return budgetErr("read_rate_limit_exceeded", "max_read_rpm", limit)
	}
	globalFiltered = append(globalFiltered, now)
	toolFiltered = append(toolFiltered, now)
	d.readRates["all_reads"] = append([]time.Time(nil), globalFiltered...)
	d.readRates[tool] = append([]time.Time(nil), toolFiltered...)
	return nil
}

func (d *Daemon) enforceTaskWindowReadBytes(windowID string, bytes int) *rpcError {
	if d == nil || bytes <= 0 {
		return nil
	}
	windowID = normalizeTaskWindowID(windowID)
	maxBytes := d.cfg.MaxTaskWindowBytes
	if maxBytes <= 0 {
		maxBytes = 16384
	}
	ttl := d.cfg.TaskWindowTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	now := time.Now().UTC()
	d.readMu.Lock()
	defer d.readMu.Unlock()

	for key, usage := range d.readWindow {
		if !usage.ExpiresAt.IsZero() && now.After(usage.ExpiresAt) {
			delete(d.readWindow, key)
		}
	}
	usage := d.readWindow[windowID]
	if usage.WindowID == "" {
		usage.WindowID = windowID
		usage.ExpiresAt = now.Add(ttl)
	}
	if !usage.ExpiresAt.IsZero() && now.After(usage.ExpiresAt) {
		usage.BytesUsed = 0
		usage.ExpiresAt = now.Add(ttl)
	}
	if usage.BytesUsed+bytes > maxBytes {
		return budgetErr("task_window_bytes_exceeded", "max_task_window_bytes", maxBytes)
	}
	usage.BytesUsed += bytes
	if usage.ExpiresAt.IsZero() {
		usage.ExpiresAt = now.Add(ttl)
	}
	d.readWindow[windowID] = usage
	return nil
}

func (d *Daemon) taskWindowUsage(windowID string) (used int, remaining int, expiresAt time.Time) {
	windowID = normalizeTaskWindowID(windowID)
	maxBytes := d.cfg.MaxTaskWindowBytes
	if maxBytes <= 0 {
		maxBytes = 16384
	}
	now := time.Now().UTC()
	d.readMu.Lock()
	defer d.readMu.Unlock()
	usage, ok := d.readWindow[windowID]
	if !ok {
		return 0, maxBytes, time.Time{}
	}
	if !usage.ExpiresAt.IsZero() && now.After(usage.ExpiresAt) {
		delete(d.readWindow, windowID)
		return 0, maxBytes, time.Time{}
	}
	remaining = maxBytes - usage.BytesUsed
	if remaining < 0 {
		remaining = 0
	}
	return usage.BytesUsed, remaining, usage.ExpiresAt
}

func normalizeTaskWindowID(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return "default"
	}
	return sanitizeOneLine(raw, "default", 128)
}

func filterRecentTimes(in []time.Time, cutoff time.Time) []time.Time {
	if len(in) == 0 {
		return nil
	}
	out := in[:0]
	for _, ts := range in {
		if ts.After(cutoff) {
			out = append(out, ts)
		}
	}
	return out
}
