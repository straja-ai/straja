package strajad

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type webDocument struct {
	ID         string
	Collection string
	URL        string
	Title      string
	Content    string
	UpdatedAt  time.Time
}

type webSearchHit struct {
	ID         string `json:"id"`
	Collection string `json:"collection"`
	URL        string `json:"url"`
	Title      string `json:"title"`
	Summary    string `json:"summary"`
	Score      int    `json:"score,omitempty"`
}

type webReaderSnippet struct {
	ID         string `json:"id"`
	Collection string `json:"collection"`
	URL        string `json:"url"`
	Title      string `json:"title"`
	Snippet    string `json:"snippet"`
	Bytes      int    `json:"bytes"`
	StartChar  int    `json:"start_char"`
	EndChar    int    `json:"end_char"`
	Redacted   bool   `json:"redacted,omitempty"`
}

type webConnector struct {
	mu        sync.RWMutex
	retrieval retrievalConfig
	docs      map[string]webDocument
	order     []string
}

func newWebConnector(retrieval retrievalConfig) *webConnector {
	now := time.Now().UTC()
	docs := map[string]webDocument{
		"web_work_001": {
			ID:         "web_work_001",
			Collection: "work",
			URL:        "https://example.com/launch-readiness",
			Title:      "Launch readiness checklist",
			Content:    "Launch readiness checklist with phased rollout guidance and escalation contacts at launch-ops@straja.ai.",
			UpdatedAt:  now.Add(-2 * time.Hour),
		},
		"web_work_002": {
			ID:         "web_work_002",
			Collection: "work",
			URL:        "https://example.com/policy-budgets",
			Title:      "Policy budgets guide",
			Content:    "Budget guidance for snippet limits, retrieval caps, and deterministic controls.",
			UpdatedAt:  now.Add(-8 * time.Hour),
		},
		"web_personal_001": {
			ID:         "web_personal_001",
			Collection: "personal",
			URL:        "https://example.com/travel-notes",
			Title:      "Travel notes and reminders",
			Content:    "Personal travel notes and reminders for spring itinerary planning.",
			UpdatedAt:  now.Add(-16 * time.Hour),
		},
		"web_tax_001": {
			ID:         "web_tax_001",
			Collection: "tax",
			URL:        "https://example.com/tax-deadlines",
			Title:      "Tax deadlines reminder",
			Content:    "Tax deadlines summary with filing references and SSN 123-45-6789 placeholder.",
			UpdatedAt:  now.Add(-28 * time.Hour),
		},
	}
	order := []string{"web_work_001", "web_work_002", "web_personal_001", "web_tax_001"}
	return &webConnector{
		retrieval: retrieval,
		docs:      docs,
		order:     order,
	}
}

func (w *webConnector) Search(query, collection string, limit int, accessCheck func(string) error) ([]webSearchHit, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

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
	candidates := make([]candidate, 0, len(w.order))
	termCounts := buildTokenCounts(query)
	queryLower := strings.ToLower(query)

	orderPos := map[string]int{}
	for i, id := range w.order {
		orderPos[id] = i
	}

	for _, id := range w.order {
		doc, ok := w.docs[id]
		if !ok {
			continue
		}
		if collection != "" && normalizeCollectionName(doc.Collection) != collection {
			continue
		}
		if accessCheck != nil {
			if err := accessCheck(doc.Collection); err != nil {
				continue
			}
		}

		searchText := strings.ToLower(strings.TrimSpace(doc.Title + " " + doc.URL + " " + doc.Content))
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

	out := make([]webSearchHit, 0, minInt(limit, len(candidates)))
	for _, c := range candidates {
		doc := w.docs[c.id]
		summary := strings.TrimSpace(doc.Title)
		if summary == "" {
			summary = "web result"
		}
		out = append(out, webSearchHit{
			ID:         doc.ID,
			Collection: doc.Collection,
			URL:        doc.URL,
			Title:      doc.Title,
			Summary:    summary,
			Score:      c.score,
		})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (w *webConnector) OpenReaderSnippet(id, rawURL, query string, maxBytes, maxCharsPerSnippet int, accessCheck func(string) error) (webReaderSnippet, bool, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	id = strings.TrimSpace(id)
	rawURL = strings.TrimSpace(rawURL)
	if id == "" && rawURL == "" {
		return webReaderSnippet{}, false, errObjectNotFound
	}
	if maxBytes <= 0 {
		maxBytes = 1024
	}
	if maxCharsPerSnippet <= 0 {
		maxCharsPerSnippet = 256
	}

	var (
		doc webDocument
		ok  bool
	)
	if id != "" {
		doc, ok = w.docs[id]
	}
	if !ok && rawURL != "" {
		for _, candidate := range w.docs {
			if strings.EqualFold(strings.TrimSpace(candidate.URL), rawURL) {
				doc = candidate
				ok = true
				break
			}
		}
	}
	if !ok {
		return webReaderSnippet{}, false, errObjectNotFound
	}
	if accessCheck != nil {
		if err := accessCheck(doc.Collection); err != nil {
			return webReaderSnippet{}, false, err
		}
	}

	selection := selectSnippet(doc.Content, query, maxCharsPerSnippet, w.retrieval)
	if selection.snippet == "" && len(strings.TrimSpace(doc.Content)) > 0 {
		return webReaderSnippet{}, false, errEgressCoverageExceeded
	}
	snippet, wasCut := bytePrefix(selection.snippet, maxBytes)
	size := len([]byte(snippet))
	if size == 0 {
		return webReaderSnippet{}, true, nil
	}
	out := webReaderSnippet{
		ID:         doc.ID,
		Collection: doc.Collection,
		URL:        doc.URL,
		Title:      doc.Title,
		Snippet:    snippet,
		Bytes:      size,
		StartChar:  selection.startChar,
		EndChar:    selection.endChar,
		Redacted:   selection.redacted,
	}
	return out, selection.truncated || wasCut, nil
}
