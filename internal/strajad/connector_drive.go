package strajad

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type driveFile struct {
	ID         string
	Collection string
	Title      string
	Path       string
	MimeType   string
	Content    string
	UpdatedAt  time.Time
}

type driveSearchHit struct {
	ID         string `json:"id"`
	Collection string `json:"collection"`
	Title      string `json:"title"`
	Path       string `json:"path"`
	MimeType   string `json:"mime_type"`
	Summary    string `json:"summary"`
	Score      int    `json:"score,omitempty"`
}

type driveSnippetHit struct {
	ID         string `json:"id"`
	Collection string `json:"collection"`
	Title      string `json:"title"`
	Path       string `json:"path"`
	MimeType   string `json:"mime_type"`
	Snippet    string `json:"snippet"`
	Bytes      int    `json:"bytes"`
	StartChar  int    `json:"start_char"`
	EndChar    int    `json:"end_char"`
	Redacted   bool   `json:"redacted,omitempty"`
}

type driveConnector struct {
	mu        sync.RWMutex
	retrieval retrievalConfig
	files     map[string]driveFile
	order     []string
}

func newDriveConnector(retrieval retrievalConfig) *driveConnector {
	now := time.Now().UTC()
	files := map[string]driveFile{
		"drive_work_001": {
			ID:         "drive_work_001",
			Collection: "work",
			Title:      "Launch Architecture Notes",
			Path:       "/work/launch/architecture-notes.md",
			MimeType:   "text/markdown",
			Content:    "Architecture notes for Q2 launch, including rollout constraints, dependency graph, and incident response draft.",
			UpdatedAt:  now.Add(-3 * time.Hour),
		},
		"drive_work_002": {
			ID:         "drive_work_002",
			Collection: "work",
			Title:      "Roadmap Planning Sheet",
			Path:       "/work/planning/roadmap.txt",
			MimeType:   "text/plain",
			Content:    "Roadmap v5 with milestones, owners, and budget checkpoints. Contact pm@straja.ai for updates.",
			UpdatedAt:  now.Add(-9 * time.Hour),
		},
		"drive_personal_001": {
			ID:         "drive_personal_001",
			Collection: "personal",
			Title:      "Travel Notes",
			Path:       "/personal/travel/itinerary.txt",
			MimeType:   "text/plain",
			Content:    "Itinerary and packing checklist for spring trip.",
			UpdatedAt:  now.Add(-12 * time.Hour),
		},
		"drive_tax_001": {
			ID:         "drive_tax_001",
			Collection: "tax",
			Title:      "Tax Worksheet Draft",
			Path:       "/tax/2025/worksheet.txt",
			MimeType:   "text/plain",
			Content:    "Estimated tax worksheet with SSN 123-45-6789 and accountant notes.",
			UpdatedAt:  now.Add(-30 * time.Hour),
		},
	}
	order := []string{"drive_work_001", "drive_work_002", "drive_personal_001", "drive_tax_001"}
	return &driveConnector{
		retrieval: retrieval,
		files:     files,
		order:     order,
	}
}

func (d *driveConnector) Search(query, collection string, limit int, accessCheck func(string) error) ([]driveSearchHit, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

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
	candidates := make([]candidate, 0, len(d.order))
	termCounts := buildTokenCounts(query)
	queryLower := strings.ToLower(query)

	orderPos := map[string]int{}
	for i, id := range d.order {
		orderPos[id] = i
	}

	for _, id := range d.order {
		file, ok := d.files[id]
		if !ok {
			continue
		}
		if collection != "" && normalizeCollectionName(file.Collection) != collection {
			continue
		}
		if accessCheck != nil {
			if err := accessCheck(file.Collection); err != nil {
				continue
			}
		}

		searchText := strings.ToLower(strings.TrimSpace(file.Title + " " + file.Path + " " + file.Content))
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

	out := make([]driveSearchHit, 0, minInt(limit, len(candidates)))
	for _, c := range candidates {
		file := d.files[c.id]
		summary := strings.TrimSpace(file.Title)
		if summary == "" {
			summary = "drive file"
		}
		out = append(out, driveSearchHit{
			ID:         file.ID,
			Collection: file.Collection,
			Title:      file.Title,
			Path:       file.Path,
			MimeType:   file.MimeType,
			Summary:    summary,
			Score:      c.score,
		})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (d *driveConnector) ReadSnippets(ids []string, query string, maxBytes, maxCharsPerSnippet int, accessCheck func(string) error) (hits []driveSnippetHit, truncated bool, missing []string, err error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

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
	out := make([]driveSnippetHit, 0, len(ids))
	notFound := make([]string, 0, len(ids))
	wasTruncated := false
	lastSnippet := ""

	for _, id := range ids {
		file, ok := d.files[strings.TrimSpace(id)]
		if !ok {
			notFound = append(notFound, strings.TrimSpace(id))
			continue
		}
		if accessCheck != nil {
			if err := accessCheck(file.Collection); err != nil {
				return nil, false, nil, err
			}
		}
		if remaining <= 0 {
			wasTruncated = true
			break
		}

		selection := selectSnippet(file.Content, query, maxCharsPerSnippet, d.retrieval)
		if selection.snippet == "" && len(strings.TrimSpace(file.Content)) > 0 {
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
		out = append(out, driveSnippetHit{
			ID:         file.ID,
			Collection: file.Collection,
			Title:      file.Title,
			Path:       file.Path,
			MimeType:   file.MimeType,
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
