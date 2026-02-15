package server

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/straja-ai/straja/internal/activation"
)

type requestStore struct {
	mu   sync.Mutex
	ttl  time.Duration
	data map[string]requestEntry
}

type requestEntry struct {
	projectID  string
	status     string
	activation *activation.Event
	createdAt  time.Time
	updatedAt  time.Time
	expiresAt  time.Time
}

type requestSnapshot struct {
	requestID string
	entry     requestEntry
}

func newRequestStore(ttl time.Duration) *requestStore {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &requestStore{
		ttl:  ttl,
		data: make(map[string]requestEntry),
	}
}

func (s *requestStore) Start(requestID, projectID string) {
	if s == nil || requestID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	now := time.Now()
	s.data[requestID] = requestEntry{
		projectID: projectID,
		status:    "pending",
		createdAt: now,
		updatedAt: now,
		expiresAt: now.Add(s.ttl),
	}
}

func (s *requestStore) Complete(requestID string, ev *activation.Event) {
	if s == nil || requestID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	now := time.Now()
	entry := requestEntry{
		status:     "completed",
		activation: ev,
		updatedAt:  now,
		expiresAt:  now.Add(s.ttl),
	}
	if existing, ok := s.data[requestID]; ok {
		entry.projectID = existing.projectID
		entry.createdAt = existing.createdAt
	} else if ev != nil {
		entry.projectID = ev.Meta.ProjectID
		entry.createdAt = now
	}
	if entry.createdAt.IsZero() {
		entry.createdAt = now
	}
	s.data[requestID] = entry
}

func (s *requestStore) Get(requestID string) (requestEntry, bool) {
	if s == nil || requestID == "" {
		return requestEntry{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	entry, ok := s.data[requestID]
	if !ok {
		return requestEntry{}, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(s.data, requestID)
		return requestEntry{}, false
	}
	return entry, true
}

func (s *requestStore) Snapshot(projectID string, limit int) []requestSnapshot {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()

	out := make([]requestSnapshot, 0, len(s.data))
	for reqID, entry := range s.data {
		if strings.TrimSpace(projectID) != "" && strings.TrimSpace(entry.projectID) != strings.TrimSpace(projectID) {
			continue
		}
		out = append(out, requestSnapshot{
			requestID: reqID,
			entry:     entry,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		li := out[i].entry.updatedAt
		lj := out[j].entry.updatedAt
		if li.IsZero() {
			li = out[i].entry.createdAt
		}
		if lj.IsZero() {
			lj = out[j].entry.createdAt
		}
		return li.After(lj)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *requestStore) cleanupLocked() {
	now := time.Now()
	for k, v := range s.data {
		if now.After(v.expiresAt) {
			delete(s.data, k)
		}
	}
}

func newRequestID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return hex.EncodeToString(buf[:])
	}
	return hex.EncodeToString(buf[:])
}
