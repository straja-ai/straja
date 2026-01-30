package server

import (
	"crypto/rand"
	"encoding/hex"
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
	expiresAt  time.Time
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
	s.data[requestID] = requestEntry{
		projectID: projectID,
		status:    "pending",
		expiresAt: time.Now().Add(s.ttl),
	}
}

func (s *requestStore) Complete(requestID string, ev *activation.Event) {
	if s == nil || requestID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	entry := requestEntry{
		status:     "completed",
		activation: ev,
		expiresAt:  time.Now().Add(s.ttl),
	}
	if existing, ok := s.data[requestID]; ok {
		entry.projectID = existing.projectID
	} else if ev != nil {
		entry.projectID = ev.ProjectID
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
