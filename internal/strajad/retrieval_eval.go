package strajad

import "strings"

type retrievalEvalQuery struct {
	Query             string
	Collection        string
	RelevantObjectIDs []string
}

type retrievalEvalStageMetrics struct {
	RecallAtK    float64 `json:"recall_at_k"`
	PrecisionAtK float64 `json:"precision_at_k"`
}

type retrievalEvalReport struct {
	K          int                       `json:"k"`
	QueryCount int                       `json:"query_count"`
	Lexical    retrievalEvalStageMetrics `json:"lexical"`
	Hybrid     retrievalEvalStageMetrics `json:"hybrid"`
	Reranked   retrievalEvalStageMetrics `json:"reranked"`
}

func (s *vaultStore) evaluateRetrievalLocked(queries []retrievalEvalQuery, k int) retrievalEvalReport {
	if k <= 0 {
		k = 5
	}
	report := retrievalEvalReport{
		K:          k,
		QueryCount: len(queries),
	}
	if len(queries) == 0 {
		return report
	}

	lexRecall := 0.0
	lexPrecision := 0.0
	hyRecall := 0.0
	hyPrecision := 0.0
	rrRecall := 0.0
	rrPrecision := 0.0

	for _, q := range queries {
		query := strings.TrimSpace(q.Query)
		collection := normalizeCollectionName(q.Collection)
		relevant := dedupeStrings(q.RelevantObjectIDs)
		if query == "" || len(relevant) == 0 {
			continue
		}
		lexicalRows := s.lexicalChunkCandidatesLocked(query, collection, maxInt(k*4, 20))
		lexicalObjects := topObjectIDsFromChunkCandidates(lexicalRows, k)
		rec, prec := stageMetricsAtK(lexicalObjects, relevant, k)
		lexRecall += rec
		lexPrecision += prec

		plan := defaultQueryExpansion(query, collection)
		hybridRows := s.collectHybridChunkCandidatesLocked(
			plan,
			collection,
			s.retrieval.maxLexicalTopN,
			s.retrieval.maxDenseTopN,
			s.retrieval.maxCandidateN,
		)
		hybridObjects := topObjectIDsFromChunkCandidates(hybridRows, k)
		rec, prec = stageMetricsAtK(hybridObjects, relevant, k)
		hyRecall += rec
		hyPrecision += prec

		rerankedRows := s.rerankCandidatesLocked(rerankInput{
			Query:     query,
			MustTerms: plan.MustTerms,
		}, hybridRows, s.retrieval.maxRerankInN, s.retrieval.maxRerankOutN)
		rerankedObjects := topObjectIDsFromChunkCandidates(rerankedRows, k)
		rec, prec = stageMetricsAtK(rerankedObjects, relevant, k)
		rrRecall += rec
		rrPrecision += prec
	}

	total := float64(len(queries))
	report.Lexical = retrievalEvalStageMetrics{
		RecallAtK:    lexRecall / total,
		PrecisionAtK: lexPrecision / total,
	}
	report.Hybrid = retrievalEvalStageMetrics{
		RecallAtK:    hyRecall / total,
		PrecisionAtK: hyPrecision / total,
	}
	report.Reranked = retrievalEvalStageMetrics{
		RecallAtK:    rrRecall / total,
		PrecisionAtK: rrPrecision / total,
	}
	return report
}

func topObjectIDsFromChunkCandidates(rows []chunkCandidate, k int) []string {
	if k <= 0 || len(rows) == 0 {
		return nil
	}
	out := make([]string, 0, k)
	seen := map[string]struct{}{}
	for _, row := range rows {
		objectID := strings.TrimSpace(row.ObjectID)
		if objectID == "" {
			continue
		}
		if _, ok := seen[objectID]; ok {
			continue
		}
		seen[objectID] = struct{}{}
		out = append(out, objectID)
		if len(out) >= k {
			break
		}
	}
	return out
}

func stageMetricsAtK(results, relevant []string, k int) (recall float64, precision float64) {
	if k <= 0 || len(relevant) == 0 {
		return 0, 0
	}
	relevantSet := map[string]struct{}{}
	for _, id := range relevant {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		relevantSet[id] = struct{}{}
	}
	if len(relevantSet) == 0 {
		return 0, 0
	}
	denom := minInt(k, len(results))
	if denom <= 0 {
		return 0, 0
	}
	hits := 0
	for i := 0; i < denom; i++ {
		if _, ok := relevantSet[strings.TrimSpace(results[i])]; ok {
			hits++
		}
	}
	recall = float64(hits) / float64(len(relevantSet))
	precision = float64(hits) / float64(denom)
	return recall, precision
}
