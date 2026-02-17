package strajad

import (
	"context"
	"strings"
)

func (d *Daemon) expandRetrievalQuery(ctx context.Context, query, collection string) queryExpansion {
	fallback := defaultQueryExpansion(query, collection)
	if d == nil || d.broker == nil {
		return fallback
	}
	expander, ok := d.broker.(retrievalQueryBroker)
	if !ok {
		return fallback
	}
	if ctx == nil {
		ctx = context.Background()
	}
	out, err := expander.ExpandRetrievalQuery(ctx, query, collection)
	if err != nil {
		return fallback
	}
	out = normalizeQueryExpansion(out, query, collection)
	merged := mergeAndGroundQueryExpansion(query, fallback, out)
	merged.ExpandedQueries = compactQueries(merged.ExpandedQueries, d.cfg.RetrievalExpandedQueries)
	if len(merged.ExpandedQueries) == 0 {
		return fallback
	}
	return merged
}

func compactQueries(queries []string, max int) []string {
	if max <= 0 {
		max = 5
	}
	out := make([]string, 0, minInt(len(queries), max))
	for _, q := range queries {
		q = strings.TrimSpace(q)
		if q == "" {
			continue
		}
		out = append(out, q)
		if len(out) >= max {
			break
		}
	}
	return dedupeStrings(out)
}

func mergeAndGroundQueryExpansion(query string, fallback, broker queryExpansion) queryExpansion {
	query = normalizeSpacing(query)
	out := queryExpansion{
		ExpandedQueries:  make([]string, 0, len(fallback.ExpandedQueries)+len(broker.ExpandedQueries)+2),
		MustTerms:        dedupeStrings(append(append([]string(nil), fallback.MustTerms...), broker.MustTerms...)),
		ShouldTerms:      dedupeStrings(append(append([]string(nil), fallback.ShouldTerms...), broker.ShouldTerms...)),
		NegativeTerms:    dedupeStrings(append(append([]string(nil), fallback.NegativeTerms...), broker.NegativeTerms...)),
		Filters:          map[string]string{},
		InferredFilters:  map[string]string{},
		SensitivityFlags: map[string]bool{},
		RiskNotes:        dedupeStrings(append(append([]string(nil), fallback.RiskNotes...), broker.RiskNotes...)),
	}
	out.ExpandedQueries = append(out.ExpandedQueries, fallback.ExpandedQueries...)
	out.ExpandedQueries = append(out.ExpandedQueries, broker.ExpandedQueries...)
	if query != "" {
		out.ExpandedQueries = append([]string{query}, out.ExpandedQueries...)
	}
	for k, v := range fallback.Filters {
		out.Filters[k] = v
	}
	for k, v := range broker.Filters {
		out.Filters[k] = v
	}
	for k, v := range fallback.InferredFilters {
		out.InferredFilters[k] = v
	}
	for k, v := range broker.InferredFilters {
		out.InferredFilters[k] = v
	}
	for k, v := range fallback.SensitivityFlags {
		out.SensitivityFlags[k] = v
	}
	for k, v := range broker.SensitivityFlags {
		out.SensitivityFlags[k] = v
	}
	out.ExpandedQueries = groundExpandedQueries(query, out.ExpandedQueries, out.MustTerms)
	return normalizeQueryExpansion(out, query, out.Filters["collection"])
}

func groundExpandedQueries(query string, candidates, mustTerms []string) []string {
	query = strings.ToLower(normalizeSpacing(query))
	anchors := retrievalQueryTokens(query)
	if len(anchors) == 0 {
		anchors = tokenizeText(query)
	}
	terms := dedupeStrings(mustTerms)
	hasSignal := func(candidate string) bool {
		candidateLower := strings.ToLower(normalizeSpacing(candidate))
		if candidateLower == "" {
			return false
		}
		if query != "" && strings.Contains(candidateLower, query) {
			return true
		}
		for _, anchor := range anchors {
			if anchor != "" && strings.Contains(candidateLower, anchor) {
				return true
			}
		}
		for _, term := range terms {
			term = strings.ToLower(strings.TrimSpace(term))
			if term != "" && strings.Contains(candidateLower, term) {
				return true
			}
		}
		return false
	}

	out := make([]string, 0, len(candidates)+1)
	if query != "" {
		out = append(out, query)
	}
	for _, candidate := range candidates {
		candidate = normalizeSpacing(candidate)
		if candidate == "" {
			continue
		}
		if hasSignal(candidate) {
			out = append(out, candidate)
		}
	}
	out = dedupeStrings(out)
	if len(out) > 0 {
		return out
	}
	// Never return an empty plan; keep original query as safe anchor.
	if query != "" {
		return []string{query}
	}
	return compactQueries(dedupeStrings(candidates), 5)
}
