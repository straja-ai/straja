package strajad

import (
	"context"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	retrievalDefaultLexicalTopN = 200
	retrievalDefaultDenseTopN   = 200
	retrievalDefaultCandidateN  = 1200
	retrievalDefaultRerankInN   = 300
	retrievalDefaultRerankOutN  = 20
	retrievalModelRerankMaxN    = 80
	retrievalModelRerankTimeout = 15 * time.Second
)

type chunkCandidate struct {
	ChunkID        string
	ObjectID       string
	CollectionID   string
	SectionID      string
	QueryMatches   []string
	LexScore       float64
	DenseScore     float64
	RRFFusionScore float64
	HybridScore    float64
	RerankScore    float64
	RationaleFlags []string
}

type rerankInput struct {
	Query     string
	MustTerms []string
}

type cachedCandidateSet struct {
	Rows      []chunkCandidate
	ExpiresAt time.Time
}

func (s *vaultStore) SearchExpanded(query string, limit int, collection string, expansion queryExpansion) ([]searchHit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return nil, err
	}
	query = strings.TrimSpace(query)
	collection = normalizeCollectionName(collection)
	if collection != "" {
		if _, err := s.requireCollectionAccessLocked(collection); err != nil {
			return nil, err
		}
	}

	plan := normalizeQueryExpansion(expansion, query, collection)
	if len(plan.ExpandedQueries) == 0 {
		return []searchHit{}, nil
	}
	cacheKey := s.retrievalCacheKeyLocked(query, collection, plan)
	var ranked []chunkCandidate
	if cached, ok := s.getRerankCacheLocked(cacheKey); ok {
		ranked = cached
	} else {
		candidates, ok := s.getCandidateCacheLocked(cacheKey)
		if !ok {
			candidates = s.collectHybridChunkCandidatesLocked(
				plan,
				collection,
				s.retrieval.maxLexicalTopN,
				s.retrieval.maxDenseTopN,
				s.retrieval.maxCandidateN,
			)
			s.setCandidateCacheLocked(cacheKey, candidates)
		}
		if len(candidates) == 0 {
			return []searchHit{}, nil
		}
		ranked = s.rerankCandidatesLocked(rerankInput{
			Query:     query,
			MustTerms: plan.MustTerms,
		}, candidates, s.retrieval.maxRerankInN, s.retrieval.maxRerankOutN)
		s.setRerankCacheLocked(cacheKey, ranked)
	}
	if len(ranked) == 0 {
		return []searchHit{}, nil
	}

	type objectAgg struct {
		score       float64
		why         []string
		chunkIDs    []string
		sectionIDs  []string
		collection  string
		objectTitle string
	}
	byObject := map[string]*objectAgg{}
	for _, row := range ranked {
		obj, ok := s.state.Objects[row.ObjectID]
		if !ok {
			continue
		}
		if collection != "" && normalizeCollectionName(obj.Collection) != collection {
			continue
		}
		if _, err := s.requireCollectionAccessLocked(obj.Collection); err != nil {
			continue
		}
		agg, ok := byObject[obj.ID]
		if !ok {
			agg = &objectAgg{
				score:       row.RerankScore,
				collection:  obj.Collection,
				objectTitle: obj.Title,
			}
			byObject[obj.ID] = agg
		}
		if row.RerankScore > agg.score {
			agg.score = row.RerankScore
		}
		agg.why = appendUniqueStrings(agg.why, row.RationaleFlags...)
		agg.chunkIDs = appendUniqueStrings(agg.chunkIDs, row.ChunkID)
		if strings.TrimSpace(row.SectionID) != "" {
			agg.sectionIDs = appendUniqueStrings(agg.sectionIDs, row.SectionID)
		}
	}

	type row struct {
		id    string
		score float64
	}
	rows := make([]row, 0, len(byObject))
	for id, agg := range byObject {
		rows = append(rows, row{id: id, score: agg.score})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].score != rows[j].score {
			return rows[i].score > rows[j].score
		}
		return rows[i].id < rows[j].id
	})

	out := make([]searchHit, 0, minInt(limit, len(rows)))
	for _, r := range rows {
		agg := byObject[r.id]
		if agg == nil {
			continue
		}
		chunkIDs := agg.chunkIDs
		if len(chunkIDs) > 3 {
			chunkIDs = chunkIDs[:3]
		}
		sections := agg.sectionIDs
		if len(sections) > 3 {
			sections = sections[:3]
		}
		why := agg.why
		if len(why) > 4 {
			why = why[:4]
		}
		out = append(out, searchHit{
			ID:               r.id,
			Collection:       agg.collection,
			Type:             objectTypeFromTitle(agg.objectTitle),
			Summary:          agg.objectTitle,
			Score:            int(r.score * 1000),
			Confidence:       confidenceSummaryForScore(r.score),
			WhyMatched:       why,
			TopSectionIDs:    sections,
			EvidenceChunkIDs: chunkIDs,
		})
		if len(out) >= limit {
			break
		}
	}
	if out == nil {
		return []searchHit{}, nil
	}
	return out, nil
}

func objectTypeFromTitle(title string) string {
	lower := strings.ToLower(strings.TrimSpace(title))
	switch {
	case strings.HasSuffix(lower, ".eml"), strings.HasSuffix(lower, ".msg"), strings.Contains(lower, "mail"):
		return "email"
	case strings.HasSuffix(lower, ".go"), strings.HasSuffix(lower, ".ts"), strings.HasSuffix(lower, ".js"), strings.HasSuffix(lower, ".py"), strings.HasSuffix(lower, ".rs"), strings.HasSuffix(lower, ".java"):
		return "repo"
	case strings.HasSuffix(lower, ".pdf"), strings.HasSuffix(lower, ".txt"), strings.HasSuffix(lower, ".md"), strings.HasSuffix(lower, ".doc"), strings.HasSuffix(lower, ".docx"):
		return "document"
	default:
		return "document"
	}
}

func confidenceSummaryForScore(score float64) string {
	switch {
	case score >= 0.70:
		return "high"
	case score >= 0.45:
		return "medium"
	default:
		return "low"
	}
}

func (s *vaultStore) collectHybridChunkCandidatesLocked(plan queryExpansion, collection string, lexicalTopN, denseTopN, candidateCap int) []chunkCandidate {
	if lexicalTopN <= 0 {
		lexicalTopN = retrievalDefaultLexicalTopN
	}
	if denseTopN <= 0 {
		denseTopN = retrievalDefaultDenseTopN
	}
	if candidateCap <= 0 {
		candidateCap = retrievalDefaultCandidateN
	}
	candidateByChunk := map[string]*chunkCandidate{}
	for _, expanded := range plan.ExpandedQueries {
		expanded = normalizeSpacing(expanded)
		if expanded == "" {
			continue
		}
		lexicalRows := s.lexicalChunkCandidatesLocked(expanded, collection, lexicalTopN)
		for rank, row := range lexicalRows {
			if !s.candidateMatchesMustTermsLocked(row.ChunkID, plan.MustTerms) {
				continue
			}
			if !s.candidateMatchesNegativeTermsLocked(row.ChunkID, plan.NegativeTerms) {
				continue
			}
			current, ok := candidateByChunk[row.ChunkID]
			if !ok {
				cp := row
				cp.QueryMatches = []string{expanded}
				cp.RRFFusionScore = rrfScoreForRank(rank + 1)
				candidateByChunk[row.ChunkID] = &cp
				continue
			}
			current.QueryMatches = appendUniqueStrings(current.QueryMatches, expanded)
			if row.LexScore > current.LexScore {
				current.LexScore = row.LexScore
			}
			current.RRFFusionScore += rrfScoreForRank(rank + 1)
			current.HybridScore = maxFloat(current.HybridScore, row.HybridScore)
			current.RationaleFlags = appendUniqueStrings(current.RationaleFlags, row.RationaleFlags...)
		}
		denseRows := s.denseChunkCandidatesLocked(expanded, collection, denseTopN)
		for rank, row := range denseRows {
			if !s.candidateMatchesMustTermsLocked(row.ChunkID, plan.MustTerms) {
				continue
			}
			if !s.candidateMatchesNegativeTermsLocked(row.ChunkID, plan.NegativeTerms) {
				continue
			}
			current, ok := candidateByChunk[row.ChunkID]
			if !ok {
				cp := row
				cp.QueryMatches = []string{expanded}
				cp.RRFFusionScore = rrfScoreForRank(rank + 1)
				candidateByChunk[row.ChunkID] = &cp
				continue
			}
			current.QueryMatches = appendUniqueStrings(current.QueryMatches, expanded)
			if row.DenseScore > current.DenseScore {
				current.DenseScore = row.DenseScore
			}
			current.RRFFusionScore += rrfScoreForRank(rank + 1)
			current.HybridScore = maxFloat(current.HybridScore, row.HybridScore)
			current.RationaleFlags = appendUniqueStrings(current.RationaleFlags, row.RationaleFlags...)
		}
	}
	rows := make([]chunkCandidate, 0, len(candidateByChunk))
	maxRRF := 0.0
	for _, row := range candidateByChunk {
		if row == nil {
			continue
		}
		if row.RRFFusionScore > maxRRF {
			maxRRF = row.RRFFusionScore
		}
		rows = append(rows, *row)
	}
	if maxRRF <= 0 {
		maxRRF = 1
	}
	for i := range rows {
		lexNorm := clampFloat(rows[i].LexScore/20.0, 0, 1)
		denseNorm := clampFloat(rows[i].DenseScore, 0, 1)
		rrfNorm := clampFloat(rows[i].RRFFusionScore/maxRRF, 0, 1)
		rows[i].HybridScore = (lexNorm * 0.25) + (denseNorm * 0.35) + (rrfNorm * 0.40)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].HybridScore != rows[j].HybridScore {
			return rows[i].HybridScore > rows[j].HybridScore
		}
		return rows[i].ChunkID < rows[j].ChunkID
	})
	if len(rows) > candidateCap {
		rows = rows[:candidateCap]
	}
	return rows
}

func (s *vaultStore) lexicalChunkCandidatesLocked(query, collection string, limit int) []chunkCandidate {
	if limit <= 0 {
		limit = retrievalDefaultLexicalTopN
	}
	query = normalizeSpacing(strings.ToLower(query))
	if query == "" {
		return nil
	}
	terms := retrievalQueryTokens(query)
	if len(terms) == 0 {
		terms = tokenizeText(query)
		if len(terms) == 0 {
			return nil
		}
	}
	totalDocs := len(s.chunkLexTokens)
	if totalDocs <= 0 {
		return nil
	}
	avgDocLen := s.avgChunkDocLenLocked()
	scores := map[string]float64{}
	termMatches := map[string]int{}
	const (
		k1 = 1.2
		b  = 0.75
	)
	for _, term := range terms {
		postings := s.chunkLexIndex[term]
		if len(postings) == 0 {
			continue
		}
		idf := bm25IDF(totalDocs, len(postings))
		for chunkID, freq := range postings {
			if freq <= 0 {
				continue
			}
			docLen := s.chunkLexDocLen[chunkID]
			if docLen <= 0 {
				docLen = 1
			}
			tf := float64(freq)
			denom := tf + k1*(1-b+b*(float64(docLen)/avgDocLen))
			if denom <= 0 {
				continue
			}
			scores[chunkID] += idf * ((tf * (k1 + 1)) / denom)
			termMatches[chunkID]++
		}
	}
	type row struct {
		chunkID string
		score   float64
	}
	rows := make([]row, 0, len(scores))
	for chunkID, score := range scores {
		chunk, ok := s.semanticChunks[chunkID]
		if !ok {
			continue
		}
		obj, ok := s.state.Objects[chunk.ObjectID]
		if !ok {
			continue
		}
		if collection != "" && normalizeCollectionName(obj.Collection) != collection {
			continue
		}
		if _, err := s.requireCollectionAccessLocked(obj.Collection); err != nil {
			continue
		}
		if termMatches[chunkID] >= minInt(2, len(terms)) {
			score += 0.35
		}
		if strings.Contains(strings.ToLower(chunk.Text), query) {
			score += 4
		}
		if strings.Contains(strings.ToLower(obj.Title), query) {
			score += 2
		}
		rows = append(rows, row{
			chunkID: chunkID,
			score:   score,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].score != rows[j].score {
			return rows[i].score > rows[j].score
		}
		return rows[i].chunkID < rows[j].chunkID
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	out := make([]chunkCandidate, 0, len(rows))
	for _, row := range rows {
		chunk := s.semanticChunks[row.chunkID]
		obj := s.state.Objects[chunk.ObjectID]
		out = append(out, chunkCandidate{
			ChunkID:      row.chunkID,
			ObjectID:     chunk.ObjectID,
			CollectionID: obj.Collection,
			SectionID:    nonEmpty(chunk.SectionID, chunk.ID),
			LexScore:     row.score,
			HybridScore:  row.score,
			RationaleFlags: []string{
				"lexical_match",
			},
		})
	}
	return out
}

func bm25IDF(totalDocs, docFreq int) float64 {
	if totalDocs <= 0 || docFreq <= 0 {
		return 0
	}
	n := float64(totalDocs)
	df := float64(docFreq)
	return math.Log(1 + ((n - df + 0.5) / (df + 0.5)))
}

func (s *vaultStore) avgChunkDocLenLocked() float64 {
	if len(s.chunkLexDocLen) == 0 {
		return 1
	}
	total := 0
	for _, docLen := range s.chunkLexDocLen {
		if docLen > 0 {
			total += docLen
		}
	}
	if total <= 0 {
		return 1
	}
	return float64(total) / float64(len(s.chunkLexDocLen))
}

func (s *vaultStore) denseChunkCandidatesLocked(query, collection string, limit int) []chunkCandidate {
	if limit <= 0 {
		limit = retrievalDefaultDenseTopN
	}
	query = strings.TrimSpace(query)
	if query == "" || len(s.semanticChunks) == 0 {
		return nil
	}
	queryVec := s.embedTextLocked(query)
	candidateIDs := s.annCandidateChunkIDsLocked(queryVec, maxInt(limit*4, 80))
	if len(candidateIDs) == 0 {
		return nil
	}
	type row struct {
		chunkID string
		score   float64
	}
	rows := make([]row, 0, len(candidateIDs))
	for _, chunkID := range candidateIDs {
		chunk, ok := s.semanticChunks[chunkID]
		if !ok {
			continue
		}
		obj, ok := s.state.Objects[chunk.ObjectID]
		if !ok {
			continue
		}
		if collection != "" && normalizeCollectionName(obj.Collection) != collection {
			continue
		}
		if _, err := s.requireCollectionAccessLocked(obj.Collection); err != nil {
			continue
		}
		score := cosineSimilarity(queryVec, chunk.Vector)
		if score <= 0 {
			continue
		}
		rows = append(rows, row{
			chunkID: chunkID,
			score:   score,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].score != rows[j].score {
			return rows[i].score > rows[j].score
		}
		return rows[i].chunkID < rows[j].chunkID
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	out := make([]chunkCandidate, 0, len(rows))
	for _, row := range rows {
		chunk := s.semanticChunks[row.chunkID]
		obj := s.state.Objects[chunk.ObjectID]
		out = append(out, chunkCandidate{
			ChunkID:      row.chunkID,
			ObjectID:     chunk.ObjectID,
			CollectionID: obj.Collection,
			SectionID:    nonEmpty(chunk.SectionID, chunk.ID),
			DenseScore:   row.score,
			HybridScore:  row.score,
			RationaleFlags: []string{
				"dense_match",
			},
		})
	}
	return out
}

func (s *vaultStore) rerankCandidatesLocked(in rerankInput, candidates []chunkCandidate, rerankIn, rerankOut int) []chunkCandidate {
	if rerankIn <= 0 {
		rerankIn = retrievalDefaultRerankInN
	}
	if rerankOut <= 0 {
		rerankOut = retrievalDefaultRerankOutN
	}
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) > rerankIn {
		candidates = append([]chunkCandidate(nil), candidates[:rerankIn]...)
	}
	maxRRF := 0.0
	for _, row := range candidates {
		if row.RRFFusionScore > maxRRF {
			maxRRF = row.RRFFusionScore
		}
	}
	if maxRRF <= 0 {
		maxRRF = 1
	}
	queryLower := strings.ToLower(normalizeSpacing(in.Query))
	queryTerms := retrievalQueryTokens(queryLower)
	queryFocus := queryLower
	if len(queryTerms) > 0 {
		queryFocus = strings.Join(queryTerms, " ")
	}
	mustTerms := compactTokens(dedupeStrings(in.MustTerms), 16)
	for i := range candidates {
		chunk, ok := s.semanticChunks[candidates[i].ChunkID]
		if !ok {
			continue
		}
		chunkText := normalizeSpacing(strings.ToLower(chunk.Text))
		if chunkText == "" {
			continue
		}
		overlap := scoreOverlap(queryFocus, chunkText)
		phraseBoost := 0.0
		if queryFocus != "" && strings.Contains(chunkText, queryFocus) {
			phraseBoost = 0.22
		} else if queryLower != "" && strings.Contains(chunkText, queryLower) {
			phraseBoost = 0.14
		}
		termBoost := 0.0
		for _, term := range queryTerms {
			if term == "" {
				continue
			}
			count := strings.Count(chunkText, term)
			if count == 0 {
				continue
			}
			termBoost += (float64(minInt(count, 2)) * 0.06) + (float64(len(term)) * 0.003)
		}
		termBoost = clampFloat(termBoost, 0, 0.22)
		mustBoost := 0.0
		if len(mustTerms) > 0 && chunkContainsAllTerms(chunkText, mustTerms) {
			mustBoost = 0.18
			candidates[i].RationaleFlags = appendUniqueStrings(candidates[i].RationaleFlags, "must_terms_satisfied")
		}
		lexNorm := clampFloat(candidates[i].LexScore/12.0, 0, 1)
		denseNorm := clampFloat(candidates[i].DenseScore, 0, 1)
		rrfNorm := clampFloat(candidates[i].RRFFusionScore/maxRRF, 0, 1)
		readabilityBoost := clampFloat(snippetReadabilityScore(chunk.Text), -0.8, 2.0) * 0.02
		candidates[i].RerankScore = (overlap * 0.42) + (denseNorm * 0.20) + (lexNorm * 0.10) + (rrfNorm * 0.10) + phraseBoost + termBoost + mustBoost + readabilityBoost
	}
	if s.retrieval.reranker != nil {
		modelN := minInt(len(candidates), retrievalModelRerankMaxN)
		docs := make([]string, 0, modelN)
		for _, row := range candidates[:modelN] {
			chunk, ok := s.semanticChunks[row.ChunkID]
			if !ok {
				docs = append(docs, "")
				continue
			}
			docs = append(docs, truncateUTF8ByBytes(chunk.Text, 1800))
		}
		rerankCtx, cancel := context.WithTimeout(context.Background(), retrievalModelRerankTimeout)
		defer cancel()
		if scores, err := s.retrieval.reranker.Score(rerankCtx, in.Query, docs); err == nil && len(scores) == len(docs) {
			for i, score := range scores {
				modelScore := clampFloat(score, 0, 1)
				candidates[i].RerankScore = (candidates[i].RerankScore * 0.6) + (modelScore * 0.4)
				candidates[i].RationaleFlags = appendUniqueStrings(candidates[i].RationaleFlags, "model_rerank")
			}
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].RerankScore != candidates[j].RerankScore {
			return candidates[i].RerankScore > candidates[j].RerankScore
		}
		if candidates[i].HybridScore != candidates[j].HybridScore {
			return candidates[i].HybridScore > candidates[j].HybridScore
		}
		return candidates[i].ChunkID < candidates[j].ChunkID
	})
	if len(candidates) > rerankOut {
		candidates = candidates[:rerankOut]
	}
	return candidates
}

func (s *vaultStore) bestChunkForObjectExpandedLocked(objectID, query string, expansion queryExpansion) (semanticChunk, bool) {
	objectID = strings.TrimSpace(objectID)
	if objectID == "" {
		return semanticChunk{}, false
	}
	plan := normalizeQueryExpansion(expansion, query, "")
	candidates := s.collectHybridChunkCandidatesLocked(plan, "", 20, 20, 80)
	if len(candidates) == 0 {
		return semanticChunk{}, false
	}
	filtered := make([]chunkCandidate, 0, len(candidates))
	for _, row := range candidates {
		if row.ObjectID != objectID {
			continue
		}
		filtered = append(filtered, row)
	}
	if len(filtered) == 0 {
		return semanticChunk{}, false
	}
	ranked := s.rerankCandidatesLocked(rerankInput{
		Query:     query,
		MustTerms: plan.MustTerms,
	}, filtered, 20, 1)
	if len(ranked) == 0 {
		return semanticChunk{}, false
	}
	best, ok := s.semanticChunks[ranked[0].ChunkID]
	return best, ok
}

func (s *vaultStore) topChunksForObjectExpandedLocked(objectID, query string, expansion queryExpansion, limit int) []semanticChunk {
	objectID = strings.TrimSpace(objectID)
	if objectID == "" {
		return nil
	}
	if limit <= 0 {
		limit = 6
	}
	limit = clampInt(limit, 1, 24)
	plan := normalizeQueryExpansion(expansion, query, "")
	candidates := s.collectHybridChunkCandidatesLocked(plan, "", 40, 40, 240)
	if len(candidates) == 0 {
		return nil
	}
	filtered := make([]chunkCandidate, 0, len(candidates))
	for _, row := range candidates {
		if row.ObjectID != objectID {
			continue
		}
		filtered = append(filtered, row)
	}
	if len(filtered) == 0 {
		return nil
	}
	ranked := s.rerankCandidatesLocked(rerankInput{
		Query:     query,
		MustTerms: plan.MustTerms,
	}, filtered, 60, limit)
	if len(ranked) == 0 {
		return nil
	}
	out := make([]semanticChunk, 0, len(ranked))
	for _, row := range ranked {
		chunk, ok := s.semanticChunks[row.ChunkID]
		if !ok {
			continue
		}
		out = append(out, chunk)
	}
	return out
}

func (s *vaultStore) candidateMatchesMustTermsLocked(chunkID string, mustTerms []string) bool {
	if len(mustTerms) == 0 {
		return true
	}
	chunk, ok := s.semanticChunks[chunkID]
	if !ok {
		return false
	}
	lower := strings.ToLower(chunk.Text)
	return chunkContainsAllTerms(lower, mustTerms)
}

func (s *vaultStore) candidateMatchesNegativeTermsLocked(chunkID string, negativeTerms []string) bool {
	if len(negativeTerms) == 0 {
		return true
	}
	chunk, ok := s.semanticChunks[chunkID]
	if !ok {
		return false
	}
	lower := strings.ToLower(chunk.Text)
	for _, term := range negativeTerms {
		term = strings.ToLower(strings.TrimSpace(term))
		if term == "" {
			continue
		}
		if strings.Contains(lower, term) {
			return false
		}
	}
	return true
}

func chunkContainsAllTerms(text string, mustTerms []string) bool {
	if len(mustTerms) == 0 {
		return true
	}
	text = strings.ToLower(text)
	for _, term := range mustTerms {
		term = strings.ToLower(strings.TrimSpace(term))
		if term == "" {
			continue
		}
		if !strings.Contains(text, term) {
			return false
		}
	}
	return true
}

func maxFloat(a, b float64) float64 {
	if a >= b {
		return a
	}
	return b
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func maxInt(a, b int) int {
	if a >= b {
		return a
	}
	return b
}

func rrfScoreForRank(rank int) float64 {
	if rank <= 0 {
		return 0
	}
	const k = 60.0
	return 1.0 / (k + float64(rank))
}

func (s *vaultStore) rebuildChunkLexicalIndexLocked() {
	s.chunkLexIndex = map[string]map[string]int{}
	s.chunkLexTokens = map[string]map[string]int{}
	s.chunkLexDocLen = map[string]int{}
	for chunkID, chunk := range s.semanticChunks {
		s.indexChunkLexicalLocked(chunkID, chunk)
	}
}

func (s *vaultStore) retrievalCacheKeyLocked(query, collection string, plan queryExpansion) string {
	normalizedQuery := normalizeSpacing(strings.ToLower(query))
	if s != nil {
		normalizedQuery = s.normalizeQueryKeyLocked(normalizedQuery)
	}
	return strings.Join([]string{
		normalizedQuery,
		normalizeCollectionName(collection),
		strings.Join(plan.ExpandedQueries, "|"),
		strings.Join(plan.MustTerms, "|"),
		strings.Join(plan.ShouldTerms, "|"),
		strings.Join(plan.NegativeTerms, "|"),
		flattenMap(plan.Filters),
		flattenMap(plan.InferredFilters),
		flattenBoolMap(plan.SensitivityFlags),
	}, "::")
}

func (s *vaultStore) getCandidateCacheLocked(key string) ([]chunkCandidate, bool) {
	if s == nil || len(s.candidateCache) == 0 {
		return nil, false
	}
	entry, ok := s.candidateCache[key]
	if !ok {
		return nil, false
	}
	now := s.cacheNowLocked()
	if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
		delete(s.candidateCache, key)
		return nil, false
	}
	return copyChunkCandidates(entry.Rows), true
}

func (s *vaultStore) setCandidateCacheLocked(key string, rows []chunkCandidate) {
	if s == nil || strings.TrimSpace(key) == "" {
		return
	}
	if s.candidateCache == nil {
		s.candidateCache = map[string]cachedCandidateSet{}
	}
	s.pruneCacheLocked(&s.candidateCache)
	s.candidateCache[key] = cachedCandidateSet{
		Rows:      copyChunkCandidates(rows),
		ExpiresAt: s.cacheNowLocked().Add(s.retrieval.cacheTTL),
	}
}

func (s *vaultStore) getRerankCacheLocked(key string) ([]chunkCandidate, bool) {
	if s == nil || len(s.rerankCache) == 0 {
		return nil, false
	}
	entry, ok := s.rerankCache[key]
	if !ok {
		return nil, false
	}
	now := s.cacheNowLocked()
	if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
		delete(s.rerankCache, key)
		return nil, false
	}
	return copyChunkCandidates(entry.Rows), true
}

func (s *vaultStore) setRerankCacheLocked(key string, rows []chunkCandidate) {
	if s == nil || strings.TrimSpace(key) == "" {
		return
	}
	if s.rerankCache == nil {
		s.rerankCache = map[string]cachedCandidateSet{}
	}
	s.pruneCacheLocked(&s.rerankCache)
	s.rerankCache[key] = cachedCandidateSet{
		Rows:      copyChunkCandidates(rows),
		ExpiresAt: s.cacheNowLocked().Add(s.retrieval.cacheTTL),
	}
}

func (s *vaultStore) pruneCacheLocked(cache *map[string]cachedCandidateSet) {
	if cache == nil || *cache == nil {
		return
	}
	now := s.cacheNowLocked()
	for key, entry := range *cache {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			delete(*cache, key)
		}
	}
	maxEntries := s.retrieval.maxCacheEntries
	if maxEntries <= 0 {
		maxEntries = 1024
	}
	if len(*cache) <= maxEntries {
		return
	}
	// Deterministic fallback eviction: drop oldest entries first.
	type row struct {
		key       string
		expiresAt time.Time
	}
	rows := make([]row, 0, len(*cache))
	for key, entry := range *cache {
		rows = append(rows, row{key: key, expiresAt: entry.ExpiresAt})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].expiresAt.Equal(rows[j].expiresAt) {
			return rows[i].key < rows[j].key
		}
		return rows[i].expiresAt.Before(rows[j].expiresAt)
	})
	for i := 0; i < len(rows)-maxEntries; i++ {
		delete(*cache, rows[i].key)
	}
}

func (s *vaultStore) cacheNowLocked() time.Time {
	if s.cacheClock != nil {
		return s.cacheClock().UTC()
	}
	return time.Now().UTC()
}

func copyChunkCandidates(in []chunkCandidate) []chunkCandidate {
	if len(in) == 0 {
		return nil
	}
	out := make([]chunkCandidate, 0, len(in))
	for _, row := range in {
		cp := row
		cp.QueryMatches = append([]string(nil), row.QueryMatches...)
		cp.RationaleFlags = append([]string(nil), row.RationaleFlags...)
		out = append(out, cp)
	}
	return out
}

func flattenMap(in map[string]string) string {
	if len(in) == 0 {
		return ""
	}
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+in[key])
	}
	return strings.Join(parts, ",")
}

func flattenBoolMap(in map[string]bool) string {
	if len(in) == 0 {
		return ""
	}
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+boolString(in[key]))
	}
	return strings.Join(parts, ",")
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func (s *vaultStore) indexChunkLexicalLocked(chunkID string, chunk semanticChunk) {
	if strings.TrimSpace(chunkID) == "" {
		return
	}
	if s.chunkLexIndex == nil {
		s.chunkLexIndex = map[string]map[string]int{}
	}
	if s.chunkLexTokens == nil {
		s.chunkLexTokens = map[string]map[string]int{}
	}
	if s.chunkLexDocLen == nil {
		s.chunkLexDocLen = map[string]int{}
	}
	obj := vaultObject{}
	if s.state != nil {
		obj = s.state.Objects[chunk.ObjectID]
	}
	tokenCounts, docLen := buildWeightedChunkTokenCounts(chunk, obj)
	if len(tokenCounts) == 0 {
		s.chunkLexTokens[chunkID] = map[string]int{}
		s.chunkLexDocLen[chunkID] = maxInt(docLen, 1)
		return
	}
	s.chunkLexTokens[chunkID] = tokenCounts
	s.chunkLexDocLen[chunkID] = maxInt(docLen, 1)
	for token, freq := range tokenCounts {
		postings := s.chunkLexIndex[token]
		if postings == nil {
			postings = map[string]int{}
			s.chunkLexIndex[token] = postings
		}
		postings[chunkID] = freq
	}
}

func (s *vaultStore) unindexChunkLexicalLocked(chunkID string) {
	if s.chunkLexIndex == nil || s.chunkLexTokens == nil {
		return
	}
	tokens := s.chunkLexTokens[chunkID]
	for token := range tokens {
		postings := s.chunkLexIndex[token]
		delete(postings, chunkID)
		if len(postings) == 0 {
			delete(s.chunkLexIndex, token)
		}
	}
	delete(s.chunkLexTokens, chunkID)
	if s.chunkLexDocLen != nil {
		delete(s.chunkLexDocLen, chunkID)
	}
}

func buildWeightedChunkTokenCounts(chunk semanticChunk, obj vaultObject) (map[string]int, int) {
	bodyCounts := buildTokenCounts(chunk.Text)
	docLen := sumTokenCounts(bodyCounts)
	if len(bodyCounts) == 0 {
		return map[string]int{}, 0
	}
	out := make(map[string]int, len(bodyCounts)+24)
	addWeightedTokens(out, bodyCounts, 1)
	// Boost document metadata fields for stronger lexical recall.
	addWeightedTokens(out, buildTokenCounts(obj.Title), 4)
	addWeightedTokens(out, buildTokenCounts(chunk.SectionKind), 2)
	if sectionLabel := sectionLabelFromID(chunk.SectionID); sectionLabel != "" {
		addWeightedTokens(out, buildTokenCounts(sectionLabel), 2)
	}
	if strings.TrimSpace(obj.Collection) != "" {
		addWeightedTokens(out, buildTokenCounts(obj.Collection), 1)
	}
	return out, docLen
}

func addWeightedTokens(dst map[string]int, src map[string]int, weight int) {
	if len(src) == 0 || weight <= 0 {
		return
	}
	for token, freq := range src {
		if token == "" || freq <= 0 {
			continue
		}
		dst[token] += freq * weight
	}
}

func sumTokenCounts(counts map[string]int) int {
	if len(counts) == 0 {
		return 0
	}
	total := 0
	for _, count := range counts {
		if count > 0 {
			total += count
		}
	}
	return total
}

func sectionLabelFromID(sectionID string) string {
	sectionID = strings.TrimSpace(strings.ToLower(sectionID))
	if sectionID == "" {
		return ""
	}
	switch {
	case strings.Contains(sectionID, "::section_doc_"):
		return "document"
	case strings.Contains(sectionID, "::section_email_"):
		return "email message"
	case strings.Contains(sectionID, "::section_repo_"):
		return "code symbol"
	default:
		return ""
	}
}
