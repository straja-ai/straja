package strajad

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type githubDoc struct {
	ID         string
	Collection string
	Repo       string
	Kind       string
	Title      string
	Path       string
	Content    string
	UpdatedAt  time.Time
}

type githubSearchHit struct {
	ID         string `json:"id"`
	Collection string `json:"collection"`
	Repo       string `json:"repo"`
	Kind       string `json:"kind"`
	Title      string `json:"title"`
	Path       string `json:"path"`
	Summary    string `json:"summary"`
	Score      int    `json:"score,omitempty"`
}

type githubSnippetHit struct {
	ID         string `json:"id"`
	Collection string `json:"collection"`
	Repo       string `json:"repo"`
	Kind       string `json:"kind"`
	Title      string `json:"title"`
	Path       string `json:"path"`
	Snippet    string `json:"snippet"`
	Bytes      int    `json:"bytes"`
	StartChar  int    `json:"start_char"`
	EndChar    int    `json:"end_char"`
	Redacted   bool   `json:"redacted,omitempty"`
}

type githubConnector struct {
	mu        sync.RWMutex
	retrieval retrievalConfig
	docs      map[string]githubDoc
	order     []string
}

func newGitHubConnector(retrieval retrievalConfig) *githubConnector {
	now := time.Now().UTC()
	docs := map[string]githubDoc{
		"github_work_001": {
			ID:         "github_work_001",
			Collection: "work",
			Repo:       "straja-ai/straja",
			Kind:       "readme",
			Title:      "README rollout notes",
			Path:       "README.md",
			Content:    "Release rollout checklist and launch notes for Straja Vault. Contact eng-lead@straja.ai for release signoff.",
			UpdatedAt:  now.Add(-4 * time.Hour),
		},
		"github_work_002": {
			ID:         "github_work_002",
			Collection: "work",
			Repo:       "straja-ai/straja",
			Kind:       "issue",
			Title:      "Issue #142: Vault policy edge cases",
			Path:       "issues/142",
			Content:    "Track policy edge cases for snippet redaction and collection boundaries.",
			UpdatedAt:  now.Add(-10 * time.Hour),
		},
		"github_personal_001": {
			ID:         "github_personal_001",
			Collection: "personal",
			Repo:       "stelo/home-automation",
			Kind:       "readme",
			Title:      "Weekend automation notes",
			Path:       "README.md",
			Content:    "Personal home automation experiments for weekend setup.",
			UpdatedAt:  now.Add(-14 * time.Hour),
		},
		"github_tax_001": {
			ID:         "github_tax_001",
			Collection: "tax",
			Repo:       "stelo/private-ledger",
			Kind:       "issue",
			Title:      "Tax filing checklist draft",
			Path:       "issues/55",
			Content:    "Tax filing checklist with SSN 123-45-6789 placeholder and accounting TODO list.",
			UpdatedAt:  now.Add(-26 * time.Hour),
		},
	}
	order := []string{"github_work_001", "github_work_002", "github_personal_001", "github_tax_001"}
	return &githubConnector{
		retrieval: retrieval,
		docs:      docs,
		order:     order,
	}
}

func (g *githubConnector) Search(query, collection string, limit int, accessCheck func(string) error) ([]githubSearchHit, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

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
	candidates := make([]candidate, 0, len(g.order))
	termCounts := buildTokenCounts(query)
	queryLower := strings.ToLower(query)

	orderPos := map[string]int{}
	for i, id := range g.order {
		orderPos[id] = i
	}

	for _, id := range g.order {
		doc, ok := g.docs[id]
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

		searchText := strings.ToLower(strings.TrimSpace(doc.Title + " " + doc.Path + " " + doc.Repo + " " + doc.Content))
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

	out := make([]githubSearchHit, 0, minInt(limit, len(candidates)))
	for _, c := range candidates {
		doc := g.docs[c.id]
		summary := strings.TrimSpace(doc.Title)
		if summary == "" {
			summary = "github item"
		}
		out = append(out, githubSearchHit{
			ID:         doc.ID,
			Collection: doc.Collection,
			Repo:       doc.Repo,
			Kind:       doc.Kind,
			Title:      doc.Title,
			Path:       doc.Path,
			Summary:    summary,
			Score:      c.score,
		})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (g *githubConnector) ReadSnippets(ids []string, query string, maxBytes, maxCharsPerSnippet int, accessCheck func(string) error) (hits []githubSnippetHit, truncated bool, missing []string, err error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

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
	out := make([]githubSnippetHit, 0, len(ids))
	notFound := make([]string, 0, len(ids))
	wasTruncated := false
	lastSnippet := ""

	for _, id := range ids {
		doc, ok := g.docs[strings.TrimSpace(id)]
		if !ok {
			notFound = append(notFound, strings.TrimSpace(id))
			continue
		}
		if accessCheck != nil {
			if err := accessCheck(doc.Collection); err != nil {
				return nil, false, nil, err
			}
		}
		if remaining <= 0 {
			wasTruncated = true
			break
		}

		selection := selectSnippet(doc.Content, query, maxCharsPerSnippet, g.retrieval)
		if selection.snippet == "" && len(strings.TrimSpace(doc.Content)) > 0 {
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
		out = append(out, githubSnippetHit{
			ID:         doc.ID,
			Collection: doc.Collection,
			Repo:       doc.Repo,
			Kind:       doc.Kind,
			Title:      doc.Title,
			Path:       doc.Path,
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
