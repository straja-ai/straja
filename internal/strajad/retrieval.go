package strajad

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	errUnsupportedContentType = errors.New("unsupported content type")
	errInvalidBase64Content   = errors.New("invalid base64 content")
	errExtractedContentEmpty  = errors.New("extracted content is empty")
	errEgressOverlapDetected  = errors.New("egress overlap detected")
	errEgressCoverageExceeded = errors.New("egress coverage exceeded")
)

const snippetNonTextPlaceholder = "[non-text content omitted]"

var (
	emailPattern      = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
	ssnPattern        = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	ccPattern         = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	pdfParenText      = regexp.MustCompile(`\(([^()]+)\)`)
	pdfObjectRefText  = regexp.MustCompile(`(?i)\b\d{1,6}\s+\d{1,3}\s+r\b`)
	pdfObjectHeader   = regexp.MustCompile(`(?i)\b\d{1,6}\s+\d{1,3}\s+obj\b`)
	pdfOperatorTokens = regexp.MustCompile(`(?i)\b(?:stream|endstream|obj|endobj|xref|trailer|startxref)\b`)
	pdfDictTokens     = regexp.MustCompile(`(?i)/(?:cs|devicecmyk|devicergb|devicegray|procset|colorspace|extgstate|xobject|illustrator|transparency|type|filter|length|kids|count|subtype|parent|bounds|domain|encode|func|bbox|matrix|resources|group)\b`)
	pdfAngleTokens    = regexp.MustCompile(`<<|>>`)
	pdfSlashTokens    = regexp.MustCompile(`(?i)/[a-z][a-z0-9_]{2,}`)
	printableWordRuns = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9,.;:_/\-() ]{2,}`)
)

type retrievalConfig struct {
	maxSnippetChars    int
	maxReadCoverage    float64
	cacheTTL           time.Duration
	profile            string
	indexMeta          retrievalIndexMeta
	embedder           embeddingProvider
	reranker           rerankerProvider
	annProvider        string
	hnswM              int
	hnswEfConstruction int
	hnswEfSearch       int
	hnswMaxElements    int
	maxLexicalTopN     int
	maxDenseTopN       int
	maxCandidateN      int
	maxRerankInN       int
	maxRerankOutN      int
	iterativePasses    int
	secondPassAddN     int
	maxCacheEntries    int
}

type retrievalIndexMeta struct {
	Version             string `json:"version"`
	EmbeddingBackend    string `json:"embedding_backend"`
	EmbeddingModel      string `json:"embedding_model"`
	EmbeddingDim        int    `json:"embedding_dim,omitempty"`
	ChunkingVersion     string `json:"chunking_version"`
	LexicalIndexVersion string `json:"lexical_index_version,omitempty"`
	ANNVersion          string `json:"ann_version"`
	HNSWM               int    `json:"hnsw_m,omitempty"`
	HNSWEfConstruction  int    `json:"hnsw_ef_construction,omitempty"`
	RerankerVersion     string `json:"reranker_version"`
}

type queryExpansion struct {
	ExpandedQueries  []string          `json:"expanded_queries"`
	MustTerms        []string          `json:"must_terms,omitempty"`
	ShouldTerms      []string          `json:"should_terms,omitempty"`
	NegativeTerms    []string          `json:"negative_terms,omitempty"`
	Filters          map[string]string `json:"filters,omitempty"`
	InferredFilters  map[string]string `json:"inferred_filters,omitempty"`
	SensitivityFlags map[string]bool   `json:"sensitivity_flags,omitempty"`
	RiskNotes        []string          `json:"risk_notes,omitempty"`
}

type snippetSelection struct {
	snippet   string
	startChar int
	endChar   int
	truncated bool
	redacted  bool
}

func tokenizeText(s string) []string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return nil
	}
	var (
		out []string
		b   strings.Builder
	)
	flush := func() {
		if b.Len() == 0 {
			return
		}
		token := b.String()
		b.Reset()
		if len(token) < 2 {
			return
		}
		out = append(out, token)
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return out
}

func retrievalQueryTokens(query string) []string {
	tokens := tokenizeText(strings.ToLower(strings.TrimSpace(query)))
	if len(tokens) == 0 {
		return nil
	}
	filtered := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		if len(tok) < 2 {
			continue
		}
		if isStopToken(tok) {
			continue
		}
		filtered = append(filtered, tok)
	}
	filtered = dedupeStrings(filtered)
	if len(filtered) > 0 {
		return filtered
	}
	return dedupeStrings(tokens)
}

func buildTokenCounts(text string) map[string]int {
	tokens := tokenizeText(text)
	if len(tokens) == 0 {
		return map[string]int{}
	}
	counts := make(map[string]int, len(tokens))
	for _, tok := range tokens {
		counts[tok]++
	}
	return counts
}

func decodeIngestContent(contentBase64, text string) ([]byte, error) {
	contentBase64 = strings.TrimSpace(contentBase64)
	if contentBase64 != "" {
		raw, err := base64.StdEncoding.DecodeString(contentBase64)
		if err != nil {
			return nil, errInvalidBase64Content
		}
		return raw, nil
	}
	return []byte(text), nil
}

func extractContentByType(contentType string, raw []byte, maxExtractedChars int) (string, bool, error) {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	switch {
	case strings.HasPrefix(contentType, "text/plain"), contentType == "":
		return truncateText(string(raw), maxExtractedChars), len([]rune(string(raw))) > maxExtractedChars, nil
	case strings.HasPrefix(contentType, "application/pdf"):
		text, truncated := extractTextFromPDF(raw, maxExtractedChars)
		if strings.TrimSpace(text) == "" {
			return "", false, errExtractedContentEmpty
		}
		return text, truncated, nil
	default:
		return "", false, fmt.Errorf("%w: %s", errUnsupportedContentType, contentType)
	}
}

func truncateText(s string, maxChars int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\x00", " "))
	if maxChars <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= maxChars {
		return s
	}
	return strings.TrimSpace(string(r[:maxChars]))
}

func extractTextFromPDF(raw []byte, maxChars int) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	if text, truncated, ok := extractTextFromPDFViaTextutil(raw, maxChars); ok {
		return text, truncated
	}
	return extractTextFromPDFHeuristic(raw, maxChars)
}

func extractTextFromPDFHeuristic(raw []byte, maxChars int) (string, bool) {
	src := string(raw)
	matches := pdfParenText.FindAllStringSubmatch(src, -1)
	parts := make([]string, 0, len(matches)+64)
	seen := map[string]struct{}{}
	type scoredCandidate struct {
		text  string
		score float64
	}
	candidates := make([]scoredCandidate, 0, len(matches)+128)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		if clean := normalizePDFCandidate(m[1]); clean != "" {
			if _, ok := seen[clean]; ok {
				continue
			}
			seen[clean] = struct{}{}
			candidates = append(candidates, scoredCandidate{
				text:  clean,
				score: pdfCandidateScore(clean),
			})
		}
	}
	for _, candidate := range printableWordRuns.FindAllString(src, -1) {
		if clean := normalizePDFCandidate(candidate); clean != "" {
			if _, ok := seen[clean]; ok {
				continue
			}
			seen[clean] = struct{}{}
			candidates = append(candidates, scoredCandidate{
				text:  clean,
				score: pdfCandidateScore(clean),
			})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return len(candidates[i].text) > len(candidates[j].text)
	})
	maxCandidateChars := 120000
	if maxChars > 0 {
		maxCandidateChars = clampInt(maxChars*6, maxChars, 240000)
	}
	for _, candidate := range candidates {
		if candidate.score < 10 {
			continue
		}
		clean := cleanPDFExtractedText(candidate.text)
		if clean == "" || looksLikeLowQualityPDFText(clean) {
			continue
		}
		parts = append(parts, clean)
		if len([]rune(strings.Join(parts, " "))) >= maxCandidateChars {
			break
		}
	}
	joined := normalizeSpacing(strings.Join(parts, " "))
	if joined == "" {
		return "", false
	}
	if maxChars <= 0 {
		return joined, false
	}
	r := []rune(joined)
	if len(r) <= maxChars {
		return joined, false
	}
	return string(r[:maxChars]), true
}

func extractTextFromPDFViaTextutil(raw []byte, maxChars int) (string, bool, bool) {
	tmpFile, err := os.CreateTemp("", "straja-pdf-*.pdf")
	if err != nil {
		return "", false, false
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", false, false
	}
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return "", false, false
	}

	cmd := exec.Command("textutil", "-convert", "txt", "-stdout", tmpPath)
	out, err := cmd.Output()
	if err != nil {
		return "", false, false
	}
	rawText := normalizeSpacing(string(out))
	if rawText == "" {
		return "", false, false
	}
	if looksLikeRawPDFDump(rawText) {
		return "", false, false
	}
	text := cleanPDFExtractedText(rawText)
	if text == "" {
		return "", false, false
	}
	// If textutil output is still highly unreadable after cleanup, fallback to heuristic extraction.
	if looksLikeLowQualityPDFText(text) && snippetReadabilityScore(text) < 0.65 {
		return "", false, false
	}
	if maxChars <= 0 {
		return text, false, true
	}
	r := []rune(text)
	if len(r) <= maxChars {
		return text, false, true
	}
	return strings.TrimSpace(string(r[:maxChars])), true, true
}

func cleanPDFExtractedText(s string) string {
	s = normalizeSpacing(s)
	if s == "" {
		return ""
	}
	s = sanitizePDFObjectNoise(s)
	s = normalizeSpacing(pdfOperatorTokens.ReplaceAllString(s, " "))
	s = normalizeSpacing(pdfDictTokens.ReplaceAllString(s, " "))
	s = normalizeSpacing(pdfAngleTokens.ReplaceAllString(s, " "))
	s = joinSpelledLetterRuns(s)
	return normalizeSpacing(s)
}

func normalizePDFCandidate(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\\", ""))
	if s == "" {
		return ""
	}
	if looksLikeRawPDFMetadataLine(s) {
		return ""
	}
	if isBase64LikeBlob(s) {
		return ""
	}
	if strings.Count(s, ":") >= 2 {
		return ""
	}

	runes := []rune(s)
	var b strings.Builder
	b.Grow(len(runes))
	for i, r := range runes {
		if unicode.IsControl(r) {
			b.WriteRune(' ')
			continue
		}
		if (r == '.' || r == '_' || r == '|' || r == '/') &&
			i > 0 &&
			i < len(runes)-1 &&
			(unicode.IsLetter(runes[i-1]) || unicode.IsDigit(runes[i-1])) &&
			(unicode.IsLetter(runes[i+1]) || unicode.IsDigit(runes[i+1])) {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	clean := normalizeSpacing(b.String())
	clean = joinSpelledLetterRuns(clean)
	clean = trimPDFTokenPrefix(clean)
	clean = cleanPDFExtractedText(clean)
	if clean == "" || looksLikeRawPDFMetadataLine(clean) || isBase64LikeBlob(clean) {
		return ""
	}
	if looksLikeLowQualityPDFText(clean) {
		return ""
	}

	alpha := 0
	longWords := 0
	for _, token := range strings.Fields(clean) {
		if len(token) >= 3 {
			longWords++
		}
		for _, r := range token {
			if unicode.IsLetter(r) {
				alpha++
			}
		}
	}
	if alpha < 6 || longWords < 2 {
		return ""
	}
	return clean
}

func trimPDFTokenPrefix(s string) string {
	tokens := strings.Fields(s)
	if len(tokens) == 0 {
		return ""
	}
	start := 0
	for start < len(tokens) {
		token := tokens[start]
		letters := 0
		digits := 0
		for _, r := range token {
			if unicode.IsLetter(r) {
				letters++
			}
			if unicode.IsDigit(r) {
				digits++
			}
		}
		if letters >= 3 {
			break
		}
		if letters == 0 && digits > 0 {
			start++
			continue
		}
		if letters > 0 && digits > 0 && len(token) <= 6 {
			start++
			continue
		}
		break
	}
	if start >= len(tokens) {
		return ""
	}
	return strings.Join(tokens[start:], " ")
}

func pdfCandidateScore(s string) float64 {
	if s == "" {
		return 0
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "xmlns") ||
		strings.Contains(lower, "rdf") ||
		strings.Contains(lower, "xmp") ||
		strings.Contains(lower, "uuid:") ||
		strings.Contains(lower, "http://") ||
		strings.Contains(lower, "https://") ||
		strings.Contains(lower, ".eps") ||
		strings.Contains(lower, ".tif") {
		return -100
	}

	alpha := 0
	digits := 0
	punct := 0
	for _, r := range s {
		switch {
		case unicode.IsLetter(r):
			alpha++
		case unicode.IsDigit(r):
			digits++
		case unicode.IsSpace(r):
		default:
			punct++
		}
	}
	words := strings.Fields(lower)
	if len(words) == 0 {
		return 0
	}
	stopwords := map[string]struct{}{
		"the": {}, "and": {}, "to": {}, "of": {}, "is": {}, "with": {}, "for": {}, "when": {}, "will": {}, "system": {},
	}
	stopwordHits := 0
	for _, w := range words {
		if _, ok := stopwords[w]; ok {
			stopwordHits++
		}
	}
	wordScore := float64(minInt(len(words), 20)) * 2.0
	alphaScore := float64(alpha) * 0.8
	digitPenalty := float64(digits) * 0.35
	punctPenalty := float64(punct) * 0.5
	stopwordBonus := float64(minInt(stopwordHits, 6)) * 3.5
	return math.Round((wordScore + alphaScore + stopwordBonus - digitPenalty - punctPenalty) * 100 / 100)
}

func looksLikeRawPDFDump(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(lower, "%pdf-") {
		return true
	}
	if strings.Contains(lower, "endobj") && strings.Contains(lower, " obj") {
		return true
	}
	return false
}

func looksLikeLowQualityPDFText(s string) bool {
	s = normalizeSpacing(strings.ToLower(s))
	if s == "" {
		return false
	}
	if looksLikePDFOperatorNoise(s) {
		return true
	}
	refCount := len(pdfObjectRefText.FindAllStringIndex(s, -1))
	if refCount >= 8 {
		return true
	}
	letters := 0
	digits := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			letters++
		}
		if unicode.IsDigit(r) {
			digits++
		}
	}
	if refCount >= 3 && digits > (letters*2) {
		return true
	}
	return false
}

func looksLikeRawPDFMetadataLine(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	if lower == "" {
		return true
	}
	if strings.HasPrefix(lower, "%pdf-") ||
		strings.HasPrefix(lower, "xref") ||
		strings.HasPrefix(lower, "trailer") ||
		strings.HasPrefix(lower, "startxref") ||
		strings.HasPrefix(lower, "endobj") ||
		strings.HasPrefix(lower, "obj") ||
		strings.HasPrefix(lower, "/type") ||
		strings.HasPrefix(lower, "/length") ||
		strings.HasPrefix(lower, "/filter") ||
		strings.HasPrefix(lower, "/kids") ||
		strings.HasPrefix(lower, "/count") ||
		strings.HasPrefix(lower, "<<") ||
		strings.HasPrefix(lower, ">>") {
		return true
	}
	if strings.Contains(lower, "<x:xmpmeta") ||
		strings.Contains(lower, "rdf:description") ||
		strings.Contains(lower, "xmpgimg:image") ||
		strings.Contains(lower, "xml:lang") {
		return true
	}
	return false
}

func isBase64LikeBlob(s string) bool {
	if len(s) < 32 {
		return false
	}
	if strings.ContainsAny(s, " \t\n\r") {
		return false
	}
	allowed := 0
	for _, r := range s {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '+' || r == '/' || r == '=' || r == '-' || r == '_' {
			allowed++
		}
	}
	return float64(allowed)/float64(len(s)) > 0.95
}

func normalizeSpacing(s string) string {
	if s == "" {
		return ""
	}
	fields := strings.Fields(s)
	return strings.TrimSpace(strings.Join(fields, " "))
}

func rankFTSMatches(objects map[string]vaultObject, order []string, index map[string]map[string]int, query string, collection string) []rankedObject {
	queryLower := strings.ToLower(strings.TrimSpace(query))
	terms := retrievalQueryTokens(queryLower)
	scores := map[string]int{}

	for _, term := range terms {
		postings := index[term]
		for id, freq := range postings {
			obj, ok := objects[id]
			if !ok {
				continue
			}
			if collection != "" && normalizeCollectionName(obj.Collection) != collection {
				continue
			}
			scores[id] += freq
		}
	}

	if len(scores) == 0 && queryLower != "" {
		for id, obj := range objects {
			if collection != "" && normalizeCollectionName(obj.Collection) != collection {
				continue
			}
			text := strings.ToLower(obj.Title + " " + obj.Content)
			if strings.Contains(text, queryLower) {
				scores[id] = 1
			}
		}
	}

	orderPos := map[string]int{}
	for i, id := range order {
		orderPos[id] = i
	}

	out := make([]rankedObject, 0, len(scores))
	for id, score := range scores {
		obj, ok := objects[id]
		if !ok {
			continue
		}
		if queryLower != "" && strings.Contains(strings.ToLower(obj.Title+" "+obj.Content), queryLower) {
			score += 5
		}
		out = append(out, rankedObject{
			id:    id,
			score: score,
			order: orderPos[id],
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].order < out[j].order
	})
	return out
}

type rankedObject struct {
	id    string
	score int
	order int
}

func selectSnippet(content, query string, maxChars int, cfg retrievalConfig) snippetSelection {
	content = normalizeSpacing(content)
	if maxChars <= 0 {
		maxChars = cfg.maxSnippetChars
	}
	if maxChars <= 0 {
		maxChars = 512
	}
	runes := []rune(content)
	totalChars := len(runes)
	if totalChars == 0 {
		return snippetSelection{}
	}

	start := selectSnippetStart(runes, query, maxChars)
	end := start + maxChars
	if end > totalChars {
		end = totalChars
	}
	if start > end {
		start = 0
	}

	coverage := float64(end-start) / float64(totalChars)
	if totalChars > (maxChars*2) && coverage > cfg.maxReadCoverage {
		return snippetSelection{
			startChar: start,
			endChar:   end,
			truncated: true,
			snippet:   "",
		}
	}

	snip := string(runes[start:end])
	cleanSnippet := sanitizeSnippetText(snip)
	if strings.TrimSpace(snip) != "" && strings.TrimSpace(cleanSnippet) == "" {
		cleanSnippet = snippetNonTextPlaceholder
	}
	redacted := applySensitiveRedaction(cleanSnippet)
	return snippetSelection{
		snippet:   redacted,
		startChar: start,
		endChar:   end,
		truncated: end < totalChars,
		redacted:  redacted != cleanSnippet,
	}
}

func selectSnippetStart(runes []rune, query string, maxChars int) int {
	totalChars := len(runes)
	if totalChars == 0 {
		return 0
	}
	if maxChars <= 0 {
		maxChars = 512
	}
	content := string(runes)
	contentLower := strings.ToLower(content)
	queryLower := strings.ToLower(normalizeSpacing(query))
	queryTerms := retrievalQueryTokens(queryLower)

	candidates := []int{0}
	windowLead := maxChars / 3
	if queryLower != "" {
		if idx := strings.Index(contentLower, queryLower); idx >= 0 {
			qStart := utf8.RuneCountInString(contentLower[:idx])
			start := qStart - windowLead
			if start < 0 {
				start = 0
			}
			candidates = append(candidates, start)
		}
	}

	if len(queryTerms) > 1 {
		sort.SliceStable(queryTerms, func(i, j int) bool {
			if len(queryTerms[i]) != len(queryTerms[j]) {
				return len(queryTerms[i]) > len(queryTerms[j])
			}
			return queryTerms[i] < queryTerms[j]
		})
	}
	maxAnchors := 24
	for _, term := range queryTerms {
		searchFrom := 0
		for searchFrom < len(contentLower) {
			idx := strings.Index(contentLower[searchFrom:], term)
			if idx < 0 {
				break
			}
			absIdx := searchFrom + idx
			qStart := utf8.RuneCountInString(contentLower[:absIdx])
			start := qStart - windowLead
			if start < 0 {
				start = 0
			}
			candidates = append(candidates, start)
			if len(candidates) >= maxAnchors {
				break
			}
			searchFrom = absIdx + len(term)
		}
		if len(candidates) >= maxAnchors {
			break
		}
	}

	if len(candidates) == 1 && queryLower != "" && totalChars > maxChars {
		step := maxInt(maxChars/2, 64)
		for start := 0; start < totalChars; start += step {
			candidates = append(candidates, start)
			if len(candidates) >= maxAnchors {
				break
			}
		}
	}

	bestStart := 0
	bestScore := math.Inf(-1)
	seen := map[int]struct{}{}
	for _, candidate := range candidates {
		start := candidate
		if start < 0 {
			start = 0
		}
		if start > totalChars-1 {
			start = totalChars - 1
		}
		if _, ok := seen[start]; ok {
			continue
		}
		seen[start] = struct{}{}
		end := start + maxChars
		if end > totalChars {
			end = totalChars
		}
		if start >= end {
			continue
		}
		window := string(runes[start:end])
		score := snippetWindowScore(window, queryLower, queryTerms)
		if score > bestScore {
			bestScore = score
			bestStart = start
		}
	}
	return bestStart
}

func snippetWindowScore(window, queryLower string, queryTerms []string) float64 {
	windowLower := strings.ToLower(window)
	score := snippetReadabilityScore(window)
	if queryLower != "" && strings.Contains(windowLower, queryLower) {
		score += 8
	}
	for _, term := range queryTerms {
		if term == "" {
			continue
		}
		count := strings.Count(windowLower, term)
		if count == 0 {
			continue
		}
		score += (float64(minInt(count, 3)) * 2.5) + (float64(len(term)) * 0.2)
		if strings.Contains(windowLower, term+" is ") {
			score += 3.5
		}
		if strings.Contains(windowLower, "about "+term) {
			score += 2.5
		}
	}
	if isHowToQueryText(queryLower) {
		for _, cue := range []string{
			"press ", "hold ", "switch ", "setting ", "steps", "ready indicator",
			"conventional cruise control", "adaptive cruise control",
		} {
			if strings.Contains(windowLower, cue) {
				score += 1.1
			}
		}
	}
	if looksLikeLowQualityPDFText(windowLower) {
		score -= 6
	}
	if looksLikePDFOperatorNoise(windowLower) {
		score -= 30
	}
	if strings.Count(windowLower, "[redacted_card]") > 0 {
		score -= 20
	}
	return score
}

func scoreSnippetForQuery(snippet, query string) float64 {
	snippet = normalizeSpacing(snippet)
	if snippet == "" {
		return math.Inf(-1)
	}
	if snippet == snippetNonTextPlaceholder {
		return -100
	}
	queryLower := strings.ToLower(normalizeSpacing(query))
	queryTerms := retrievalQueryTokens(queryLower)
	score := snippetWindowScore(snippet, queryLower, queryTerms)
	if looksLikePDFOperatorNoise(snippet) {
		score -= 40
	}
	if strings.Contains(strings.ToLower(snippet), "[redacted_card]") {
		score -= 24
	}
	return score
}

func isHowToQueryText(queryLower string) bool {
	queryLower = normalizeSpacing(strings.ToLower(queryLower))
	if queryLower == "" {
		return false
	}
	return strings.Contains(queryLower, "how to") ||
		strings.Contains(queryLower, "steps") ||
		strings.Contains(queryLower, "be very specific") ||
		strings.Contains(queryLower, "instruction")
}

func snippetReadabilityScore(s string) float64 {
	s = normalizeSpacing(s)
	if s == "" {
		return 0
	}
	letters := 0
	digits := 0
	spaces := 0
	punct := 0
	for _, r := range s {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsDigit(r):
			digits++
		case unicode.IsSpace(r):
			spaces++
		case isCommonPunctuation(r):
			punct++
		}
	}
	total := len([]rune(s))
	if total == 0 {
		return 0
	}
	letterRatio := float64(letters) / float64(total)
	wordCount := len(strings.Fields(s))
	wordScore := float64(minInt(wordCount, 40)) / 12.0
	digitPenalty := float64(digits) / float64(total)
	punctPenalty := float64(maxInt(punct-spaces, 0)) / float64(total)
	return (letterRatio * 3.0) + wordScore - (digitPenalty * 1.8) - (punctPenalty * 1.4)
}

func sanitizeSnippetText(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	runes := []rune(s)
	if len(runes) == 0 {
		return ""
	}

	var (
		b           strings.Builder
		total       int
		replacement int
		controlDrop int
	)
	b.Grow(len(s))
	for _, r := range runes {
		total++
		if r == utf8.RuneError {
			replacement++
			continue
		}
		if unicode.IsControl(r) && r != '\n' && r != '\t' && r != '\r' {
			controlDrop++
			continue
		}
		b.WriteRune(r)
	}
	cleaned := normalizeSpacing(b.String())
	if cleaned == "" {
		return ""
	}
	cleaned = sanitizePDFObjectNoise(cleaned)
	if cleaned == "" {
		return snippetNonTextPlaceholder
	}
	if strings.Contains(strings.ToLower(cleaned), "[redacted_card]") && looksLikePDFOperatorNoise(cleaned) {
		return snippetNonTextPlaceholder
	}
	if looksLikePDFOperatorNoise(cleaned) && snippetReadabilityScore(cleaned) < 2.5 {
		return snippetNonTextPlaceholder
	}

	qualityTotal := 0
	qualityUnits := 0
	for _, r := range []rune(cleaned) {
		qualityTotal++
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) || isCommonPunctuation(r) {
			qualityUnits++
		}
	}
	if qualityTotal == 0 {
		return ""
	}

	if total >= 24 {
		if float64(replacement)/float64(total) > 0.03 {
			return snippetNonTextPlaceholder
		}
		if float64(replacement+controlDrop)/float64(total) > 0.10 {
			return snippetNonTextPlaceholder
		}
		if float64(qualityUnits)/float64(qualityTotal) < 0.45 {
			return snippetNonTextPlaceholder
		}
	}
	if qualityTotal <= 4 && (replacement+controlDrop) > 0 {
		return snippetNonTextPlaceholder
	}
	return cleaned
}

func sanitizePDFObjectNoise(s string) string {
	s = normalizeSpacing(s)
	if s == "" {
		return ""
	}
	s = normalizeSpacing(pdfObjectHeader.ReplaceAllString(s, " "))
	s = normalizeSpacing(pdfObjectRefText.ReplaceAllString(s, " "))
	s = normalizeSpacing(pdfOperatorTokens.ReplaceAllString(s, " "))
	s = normalizeSpacing(pdfDictTokens.ReplaceAllString(s, " "))
	s = normalizeSpacing(pdfAngleTokens.ReplaceAllString(s, " "))
	matches := pdfParenText.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return normalizeSpacing(s)
	}
	var b strings.Builder
	last := 0
	for _, loc := range matches {
		if len(loc) < 4 {
			continue
		}
		fullStart, fullEnd := loc[0], loc[1]
		innerStart, innerEnd := loc[2], loc[3]
		if fullStart > last {
			b.WriteString(s[last:fullStart])
		}
		inner := normalizeSpacing(s[innerStart:innerEnd])
		inner = trimPDFTokenPrefix(inner)
		if inner != "" && !looksLikeLowQualityPDFText(inner) {
			b.WriteString(inner)
		} else {
			b.WriteString(" ")
		}
		last = fullEnd
	}
	if last < len(s) {
		b.WriteString(s[last:])
	}
	clean := normalizeSpacing(joinSpelledLetterRuns(b.String()))
	clean = normalizeSpacing(pdfOperatorTokens.ReplaceAllString(clean, " "))
	clean = normalizeSpacing(pdfDictTokens.ReplaceAllString(clean, " "))
	clean = normalizeSpacing(pdfAngleTokens.ReplaceAllString(clean, " "))
	return clean
}

func looksLikePDFOperatorNoise(s string) bool {
	s = normalizeSpacing(strings.ToLower(s))
	if s == "" {
		return false
	}
	operatorHits := len(pdfOperatorTokens.FindAllStringIndex(s, -1))
	dictHits := len(pdfDictTokens.FindAllStringIndex(s, -1))
	angleHits := len(pdfAngleTokens.FindAllStringIndex(s, -1))
	slashHits := len(pdfSlashTokens.FindAllStringIndex(s, -1))
	if operatorHits >= 2 {
		return true
	}
	if operatorHits >= 1 && (dictHits >= 2 || angleHits >= 2) {
		return true
	}
	if dictHits >= 4 && angleHits >= 2 {
		return true
	}
	if dictHits >= 2 && slashHits >= 5 {
		return true
	}
	if strings.Count(s, "[redacted_card]") >= 1 && slashHits >= 4 {
		return true
	}
	return false
}

func joinSpelledLetterRuns(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	out := make([]string, 0, len(fields))
	for i := 0; i < len(fields); {
		j := i
		for j < len(fields) && isSingleLetterWord(fields[j]) {
			j++
		}
		if j-i >= 3 {
			var b strings.Builder
			for _, token := range fields[i:j] {
				b.WriteString(token)
			}
			out = append(out, b.String())
			i = j
			continue
		}
		out = append(out, fields[i])
		i++
	}
	return strings.Join(out, " ")
}

func isSingleLetterWord(s string) bool {
	r := []rune(strings.TrimSpace(s))
	return len(r) == 1 && unicode.IsLetter(r[0])
}

func isCommonPunctuation(r rune) bool {
	switch r {
	case '.', ',', ';', ':', '-', '_', '/', '\\', '\'', '"', '(', ')', '[', ']', '{', '}', '?', '!', '+', '#', '%', '&', '*', '=':
		return true
	default:
		return false
	}
}

func applySensitiveRedaction(s string) string {
	out := s
	out = emailPattern.ReplaceAllString(out, "[REDACTED_EMAIL]")
	out = ssnPattern.ReplaceAllString(out, "[REDACTED_SSN]")
	out = ccPattern.ReplaceAllStringFunc(out, func(v string) string {
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, v)
		if len(digits) < 13 || len(digits) > 19 {
			return v
		}
		return "[REDACTED_CARD]"
	})
	return out
}

func hasDuplicateIDs(ids []string) bool {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			return true
		}
		seen[id] = struct{}{}
	}
	return false
}

func bytePrefix(s string, maxBytes int) (string, bool) {
	if maxBytes <= 0 {
		return "", len(s) > 0
	}
	b := []byte(s)
	if len(b) <= maxBytes {
		return s, false
	}
	cut := b[:maxBytes]
	for len(cut) > 0 && !utf8.Valid(cut) {
		cut = cut[:len(cut)-1]
	}
	return string(cut), true
}

func containsAnyToken(content string, tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	lower := strings.ToLower(content)
	for _, tok := range tokens {
		if tok != "" && strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

func compactTokens(tokens []string, max int) []string {
	if len(tokens) <= max || max <= 0 {
		return tokens
	}
	return tokens[:max]
}

func defaultQueryExpansion(query, collection string) queryExpansion {
	query = normalizeSpacing(query)
	collection = normalizeCollectionName(collection)
	if query == "" {
		return queryExpansion{}
	}
	tokens := retrievalQueryTokens(query)
	should := compactTokens(dedupeStrings(tokens), 12)
	must := inferMustTerms(query)
	expanded := []string{query}
	if short := keywordFocusedVariant(query); short != "" && !strings.EqualFold(short, query) {
		expanded = append(expanded, short)
	}
	if stem := stemFocusedVariant(tokens); stem != "" && !strings.EqualFold(stem, query) {
		expanded = append(expanded, stem)
	}
	filters := map[string]string{}
	sensitivity := map[string]bool{}
	if containsBulkExportIntent(query) {
		sensitivity["bulk_export_intent"] = true
	}
	if collection != "" {
		filters["collection"] = collection
	}
	return queryExpansion{
		ExpandedQueries:  dedupeStrings(expanded),
		MustTerms:        must,
		ShouldTerms:      should,
		NegativeTerms:    inferNegativeTerms(query),
		Filters:          filters,
		SensitivityFlags: sensitivity,
		RiskNotes:        inferQueryRiskNotes(query),
	}
}

func normalizeQueryExpansion(in queryExpansion, fallbackQuery, fallbackCollection string) queryExpansion {
	out := queryExpansion{
		ExpandedQueries:  dedupeStrings(in.ExpandedQueries),
		MustTerms:        compactTokens(dedupeStrings(in.MustTerms), 16),
		ShouldTerms:      compactTokens(dedupeStrings(in.ShouldTerms), 16),
		NegativeTerms:    compactTokens(dedupeStrings(in.NegativeTerms), 16),
		Filters:          map[string]string{},
		InferredFilters:  map[string]string{},
		SensitivityFlags: map[string]bool{},
		RiskNotes:        compactTokens(dedupeStrings(in.RiskNotes), 6),
	}
	if len(out.ExpandedQueries) == 0 {
		base := normalizeSpacing(fallbackQuery)
		if base != "" {
			out.ExpandedQueries = []string{base}
		}
	}
	for _, q := range out.ExpandedQueries {
		if len([]byte(q)) > 4000 {
			out.ExpandedQueries = []string{truncateUTF8ByBytes(q, 4000)}
			break
		}
	}
	if in.Filters != nil {
		for k, v := range in.Filters {
			key := normalizeCollectionName(k)
			if key == "" {
				key = strings.ToLower(strings.TrimSpace(k))
			}
			value := strings.TrimSpace(v)
			if key == "" || value == "" {
				continue
			}
			out.Filters[key] = value
		}
	}
	if in.InferredFilters != nil {
		for k, v := range in.InferredFilters {
			key := normalizeCollectionName(k)
			if key == "" {
				key = strings.ToLower(strings.TrimSpace(k))
			}
			value := strings.TrimSpace(v)
			if key == "" || value == "" {
				continue
			}
			out.InferredFilters[key] = value
			if _, exists := out.Filters[key]; !exists {
				out.Filters[key] = value
			}
		}
	}
	for key, value := range in.SensitivityFlags {
		k := strings.TrimSpace(strings.ToLower(key))
		if k == "" {
			continue
		}
		out.SensitivityFlags[k] = value
	}
	collection := normalizeCollectionName(fallbackCollection)
	if collection != "" {
		out.Filters["collection"] = collection
	}
	if containsBulkExportIntent(strings.Join(out.ExpandedQueries, " ")) {
		out.SensitivityFlags["bulk_export_intent"] = true
	}
	return out
}

func inferMustTerms(query string) []string {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	quoted := extractQuotedPhrases(query, 6)
	if len(quoted) > 0 {
		return quoted
	}
	tokens := tokenizeText(strings.ToLower(query))
	if len(tokens) == 0 {
		return nil
	}
	out := make([]string, 0, 4)
	for _, tok := range tokens {
		if containsDigit(tok) || strings.Contains(tok, "-") || strings.Contains(tok, "_") {
			out = append(out, tok)
		}
		if len(out) >= 4 {
			break
		}
	}
	return dedupeStrings(out)
}

func keywordFocusedVariant(query string) string {
	tokens := tokenizeText(strings.ToLower(query))
	if len(tokens) == 0 {
		return ""
	}
	out := make([]string, 0, minInt(len(tokens), 8))
	for _, tok := range tokens {
		if len(tok) < 3 {
			continue
		}
		if isStopToken(tok) {
			continue
		}
		out = append(out, tok)
		if len(out) >= 8 {
			break
		}
	}
	return strings.Join(out, " ")
}

func stemFocusedVariant(tokens []string) string {
	if len(tokens) == 0 {
		return ""
	}
	out := make([]string, 0, minInt(len(tokens), 8))
	for _, tok := range tokens {
		if isStopToken(tok) {
			continue
		}
		stem := stemToken(tok)
		if len(stem) < 2 {
			continue
		}
		out = append(out, stem)
		if len(out) >= 8 {
			break
		}
	}
	return strings.Join(dedupeStrings(out), " ")
}

func extractQuotedPhrases(query string, max int) []string {
	if max <= 0 {
		max = 4
	}
	out := make([]string, 0, max)
	for _, quote := range []string{`"`, `'`} {
		parts := strings.Split(query, quote)
		if len(parts) < 3 {
			continue
		}
		for i := 1; i < len(parts); i += 2 {
			p := normalizeSpacing(parts[i])
			if p == "" {
				continue
			}
			out = append(out, p)
			if len(out) >= max {
				return dedupeStrings(out)
			}
		}
	}
	return dedupeStrings(out)
}

func inferQueryRiskNotes(query string) []string {
	lower := strings.ToLower(strings.TrimSpace(query))
	if lower == "" {
		return nil
	}
	notes := make([]string, 0, 2)
	if containsBulkExportIntent(lower) {
		notes = append(notes, "bulk_export_intent_detected")
	}
	if strings.Contains(lower, "entire mailbox") || strings.Contains(lower, "all files") || strings.Contains(lower, "full database") {
		notes = append(notes, "broad_scope_request")
	}
	return notes
}

func containsBulkExportIntent(query string) bool {
	lower := strings.ToLower(strings.TrimSpace(query))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "export all") ||
		strings.Contains(lower, "dump everything") ||
		strings.Contains(lower, "all documents") ||
		strings.Contains(lower, "full export")
}

func inferNegativeTerms(query string) []string {
	tokens := tokenizeText(strings.ToLower(query))
	if len(tokens) == 0 {
		return nil
	}
	out := make([]string, 0, 6)
	for i := 0; i < len(tokens)-1; i++ {
		switch tokens[i] {
		case "not", "without", "exclude", "except", "excluding":
			next := strings.TrimSpace(tokens[i+1])
			if next == "" || isStopToken(next) {
				continue
			}
			out = append(out, next)
		}
	}
	return dedupeStrings(out)
}

func containsDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func isStopToken(token string) bool {
	switch token {
	case "a", "an", "the", "and", "or", "for", "with", "from", "that", "this", "what", "when", "where", "about", "into", "your", "have", "show", "find", "give", "is", "are", "was", "were", "be", "to", "of", "in", "on", "at", "it", "as":
		return true
	default:
		return false
	}
}

func dedupeStrings(items []string) []string {
	if len(items) == 0 {
		return items
	}
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func joinForIndex(parts ...string) string {
	return normalizeSpacing(strings.Join(parts, " "))
}

func scoreOverlap(a, b string) float64 {
	a = normalizeSpacing(strings.ToLower(a))
	b = normalizeSpacing(strings.ToLower(b))
	if a == "" || b == "" {
		return 0
	}
	if a == b {
		return 1
	}
	aset := make(map[string]struct{})
	for _, w := range strings.Fields(a) {
		aset[w] = struct{}{}
	}
	if len(aset) == 0 {
		return 0
	}
	intersect := 0
	bset := make(map[string]struct{})
	for _, w := range strings.Fields(b) {
		bset[w] = struct{}{}
	}
	for w := range aset {
		if _, ok := bset[w]; ok {
			intersect++
		}
	}
	union := len(aset) + len(bset) - intersect
	if union == 0 {
		return 0
	}
	return float64(intersect) / float64(union)
}

func stripPDFPrefix(raw []byte) []byte {
	return bytes.TrimSpace(raw)
}
