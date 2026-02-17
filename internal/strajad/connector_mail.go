package strajad

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

var errMailDraftOnly = errors.New("mail connector is draft-first; sending is blocked")

type mailMessage struct {
	ID         string
	Collection string
	Subject    string
	From       string
	Body       string
	UpdatedAt  time.Time
}

type mailDraft struct {
	ID         string    `json:"id"`
	Collection string    `json:"collection"`
	To         string    `json:"to"`
	Subject    string    `json:"subject"`
	Body       string    `json:"body"`
	Status     string    `json:"status"`
	ApprovalID string    `json:"approval_id,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type mailSearchHit struct {
	ID         string `json:"id"`
	Collection string `json:"collection"`
	From       string `json:"from"`
	Subject    string `json:"subject"`
	Summary    string `json:"summary"`
	Score      int    `json:"score,omitempty"`
}

type mailSnippetHit struct {
	ID         string `json:"id"`
	Collection string `json:"collection"`
	From       string `json:"from"`
	Subject    string `json:"subject"`
	Snippet    string `json:"snippet"`
	Bytes      int    `json:"bytes"`
	StartChar  int    `json:"start_char"`
	EndChar    int    `json:"end_char"`
	Redacted   bool   `json:"redacted,omitempty"`
}

type mailConnector struct {
	mu        sync.RWMutex
	retrieval retrievalConfig
	messages  map[string]mailMessage
	order     []string
	drafts    map[string]mailDraft
	nextDraft int
}

func newMailConnector(retrieval retrievalConfig) *mailConnector {
	now := time.Now().UTC()
	msgs := map[string]mailMessage{
		"mail_work_001": {
			ID:         "mail_work_001",
			Collection: "work",
			Subject:    "Q2 launch schedule and release checklist",
			From:       "pm@straja.ai",
			Body:       "Please review launch checklist draft v3 and share risks by Thursday. Contact: launch-ops@straja.ai",
			UpdatedAt:  now.Add(-2 * time.Hour),
		},
		"mail_work_002": {
			ID:         "mail_work_002",
			Collection: "work",
			Subject:    "Budget approvals for infra upgrades",
			From:       "finance@straja.ai",
			Body:       "Need approval for indexing cluster expansion. Current estimate: $4,800 monthly.",
			UpdatedAt:  now.Add(-5 * time.Hour),
		},
		"mail_personal_001": {
			ID:         "mail_personal_001",
			Collection: "personal",
			Subject:    "Dinner plans",
			From:       "alex@example.com",
			Body:       "Can we do dinner Friday at 7? Text me at 555-101-2020.",
			UpdatedAt:  now.Add(-7 * time.Hour),
		},
		"mail_tax_001": {
			ID:         "mail_tax_001",
			Collection: "tax",
			Subject:    "Estimated tax reminder",
			From:       "noreply@filings.example",
			Body:       "Reminder: Q1 payment due April 15. Ref ID 123-45-6789.",
			UpdatedAt:  now.Add(-25 * time.Hour),
		},
	}
	order := []string{"mail_work_001", "mail_work_002", "mail_personal_001", "mail_tax_001"}
	return &mailConnector{
		retrieval: retrieval,
		messages:  msgs,
		order:     order,
		drafts:    map[string]mailDraft{},
		nextDraft: 1,
	}
}

func (m *mailConnector) Search(query, collection string, limit int, accessCheck func(string) error) ([]mailSearchHit, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 {
		limit = 3
	}
	query = strings.TrimSpace(query)
	collection = normalizeCollectionName(collection)

	if collection != "" && accessCheck != nil {
		if err := accessCheck(collection); err != nil {
			return nil, err
		}
	}

	type candidate struct {
		id    string
		score int
		order int
	}
	candidates := make([]candidate, 0, len(m.order))
	termCounts := buildTokenCounts(query)
	queryLower := strings.ToLower(query)

	orderPos := map[string]int{}
	for i, id := range m.order {
		orderPos[id] = i
	}

	for _, id := range m.order {
		msg, ok := m.messages[id]
		if !ok {
			continue
		}
		if collection != "" && normalizeCollectionName(msg.Collection) != collection {
			continue
		}
		if accessCheck != nil {
			if err := accessCheck(msg.Collection); err != nil {
				continue
			}
		}

		searchText := strings.ToLower(strings.TrimSpace(msg.Subject + " " + msg.Body))
		score := 0
		if len(termCounts) == 0 {
			score = 1
		} else {
			counts := buildTokenCounts(searchText)
			for term, qFreq := range termCounts {
				score += counts[term] * qFreq
			}
			if queryLower != "" && strings.Contains(searchText, queryLower) {
				score += 5
			}
		}
		if score <= 0 {
			continue
		}
		candidates = append(candidates, candidate{
			id:    id,
			score: score,
			order: orderPos[id],
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].order < candidates[j].order
	})

	out := make([]mailSearchHit, 0, minInt(limit, len(candidates)))
	for _, c := range candidates {
		msg := m.messages[c.id]
		summary := strings.TrimSpace(msg.Subject)
		if summary == "" {
			summary = "mail message"
		}
		out = append(out, mailSearchHit{
			ID:         msg.ID,
			Collection: msg.Collection,
			From:       msg.From,
			Subject:    msg.Subject,
			Summary:    summary,
			Score:      c.score,
		})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *mailConnector) ReadSnippets(ids []string, query string, maxBytes, maxCharsPerSnippet int, accessCheck func(string) error) (hits []mailSnippetHit, truncated bool, missing []string, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if hasDuplicateIDs(ids) {
		return nil, false, nil, errEgressOverlapDetected
	}
	if maxBytes <= 0 {
		maxBytes = 1024
	}
	if maxCharsPerSnippet <= 0 {
		maxCharsPerSnippet = 256
	}

	remaining := maxBytes
	out := make([]mailSnippetHit, 0, len(ids))
	notFound := make([]string, 0, len(ids))
	wasTruncated := false
	lastSnippet := ""

	for _, id := range ids {
		msg, ok := m.messages[strings.TrimSpace(id)]
		if !ok {
			notFound = append(notFound, strings.TrimSpace(id))
			continue
		}
		if accessCheck != nil {
			if err := accessCheck(msg.Collection); err != nil {
				return nil, false, nil, err
			}
		}
		if remaining <= 0 {
			wasTruncated = true
			break
		}

		selection := selectSnippet(msg.Body, query, maxCharsPerSnippet, m.retrieval)
		if selection.snippet == "" && len(strings.TrimSpace(msg.Body)) > 0 {
			return nil, false, nil, errEgressCoverageExceeded
		}
		if lastSnippet != "" && scoreOverlap(lastSnippet, selection.snippet) >= 0.95 {
			return nil, false, nil, errEgressOverlapDetected
		}
		snippet, wasCut := bytePrefix(selection.snippet, remaining)
		size := len([]byte(snippet))
		if size == 0 {
			wasTruncated = true
			break
		}
		out = append(out, mailSnippetHit{
			ID:         msg.ID,
			Collection: msg.Collection,
			From:       msg.From,
			Subject:    msg.Subject,
			Snippet:    snippet,
			Bytes:      size,
			StartChar:  selection.startChar,
			EndChar:    selection.endChar,
			Redacted:   selection.redacted,
		})
		remaining -= size
		wasTruncated = wasTruncated || wasCut || selection.truncated
		lastSnippet = snippet
	}
	return out, wasTruncated, notFound, nil
}

func (m *mailConnector) CreateDraft(collection, to, subject, body string, accessCheck func(string) error) (mailDraft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	collection = normalizeCollectionName(collection)
	if collection == "" {
		collection = "work"
	}
	if accessCheck != nil {
		if err := accessCheck(collection); err != nil {
			return mailDraft{}, err
		}
	}

	to = strings.TrimSpace(to)
	subject = strings.TrimSpace(subject)
	body = strings.TrimSpace(body)
	if to == "" || subject == "" || body == "" {
		return mailDraft{}, errors.New("to, subject, and body are required")
	}

	now := time.Now().UTC()
	draftID := fmt.Sprintf("mail_draft_%04d", m.nextDraft)
	m.nextDraft++
	out := mailDraft{
		ID:         draftID,
		Collection: collection,
		To:         to,
		Subject:    subject,
		Body:       body,
		Status:     "draft",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	m.drafts[draftID] = out
	return out, nil
}

func (m *mailConnector) GetDraft(id string, accessCheck func(string) error) (mailDraft, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return mailDraft{}, fmt.Errorf("%w: empty draft id", errObjectNotFound)
	}
	draft, ok := m.drafts[id]
	if !ok {
		return mailDraft{}, fmt.Errorf("%w: %s", errObjectNotFound, id)
	}
	if accessCheck != nil {
		if err := accessCheck(draft.Collection); err != nil {
			return mailDraft{}, err
		}
	}
	return draft, nil
}

func (m *mailConnector) MarkDraftQueuedForApproval(id, approvalID string) (mailDraft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id = strings.TrimSpace(id)
	draft, ok := m.drafts[id]
	if !ok {
		return mailDraft{}, fmt.Errorf("%w: %s", errObjectNotFound, id)
	}
	draft.Status = "queued_for_approval"
	draft.ApprovalID = strings.TrimSpace(approvalID)
	draft.Reason = ""
	draft.UpdatedAt = time.Now().UTC()
	m.drafts[id] = draft
	return draft, nil
}

func (m *mailConnector) MarkDraftApprovalDecision(id, status, reason string) (mailDraft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id = strings.TrimSpace(id)
	draft, ok := m.drafts[id]
	if !ok {
		return mailDraft{}, fmt.Errorf("%w: %s", errObjectNotFound, id)
	}
	status = strings.TrimSpace(strings.ToLower(status))
	switch status {
	case "approved":
		draft.Status = "approved_pending_external_send"
	case "rejected":
		draft.Status = "rejected"
	default:
		return mailDraft{}, errInvalidApprovalAction
	}
	draft.Reason = strings.TrimSpace(reason)
	draft.UpdatedAt = time.Now().UTC()
	m.drafts[id] = draft
	return draft, nil
}
