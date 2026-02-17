package strajad

import (
	"context"
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	semanticEmbeddingDims      = 128
	semanticChunkTargetChars   = 900
	semanticChunkOverlapChars  = 160
	semanticMaxChunksPerObject = 128
	semanticMinObjectScore     = 0.18
	semanticBoostWeight        = 4.0

	semanticANNBits           = 14
	semanticANNTables         = 6
	semanticANNCandidateLimit = 320
)

type semanticChunk struct {
	ID          string    `json:"id"`
	ObjectID    string    `json:"object_id"`
	SectionID   string    `json:"section_id,omitempty"`
	SectionKind string    `json:"section_kind,omitempty"`
	Text        string    `json:"text"`
	StartChar   int       `json:"start_char"`
	EndChar     int       `json:"end_char"`
	Vector      []float32 `json:"vector"`
}

type semanticWindow struct {
	text      string
	startChar int
	endChar   int
}

type semanticSection struct {
	id        string
	kind      string
	text      string
	startChar int
	endChar   int
}

func (s *vaultStore) syncSemanticStateLocked() {
	if s.state == nil {
		return
	}
	chunks := make(map[string]semanticChunk, len(s.semanticChunks))
	for id, chunk := range s.semanticChunks {
		cp := semanticChunk{
			ID:          chunk.ID,
			ObjectID:    chunk.ObjectID,
			SectionID:   chunk.SectionID,
			SectionKind: chunk.SectionKind,
			Text:        chunk.Text,
			StartChar:   chunk.StartChar,
			EndChar:     chunk.EndChar,
		}
		if len(chunk.Vector) > 0 {
			cp.Vector = append([]float32(nil), chunk.Vector...)
		}
		chunks[id] = cp
	}
	chunkIDs := make(map[string][]string, len(s.objectChunkIDs))
	for objectID, ids := range s.objectChunkIDs {
		chunkIDs[objectID] = append([]string(nil), ids...)
	}
	s.state.SemanticChunks = chunks
	s.state.ObjectChunkIDs = chunkIDs
}

func (s *vaultStore) loadSemanticIndexFromStateLocked() bool {
	if s.state == nil {
		return false
	}
	if !s.semanticIndexMetaCompatibleLocked() {
		return false
	}
	if len(s.state.SemanticChunks) == 0 || len(s.state.ObjectChunkIDs) == 0 {
		return false
	}
	if s.semanticChunks == nil {
		s.semanticChunks = map[string]semanticChunk{}
	}
	if s.objectChunkIDs == nil {
		s.objectChunkIDs = map[string][]string{}
	}
	if s.annBuckets == nil {
		s.annBuckets = map[uint64][]string{}
	}
	if s.chunkANNKeys == nil {
		s.chunkANNKeys = map[string][]uint64{}
	}

	for objectID, ids := range s.state.ObjectChunkIDs {
		if _, ok := s.state.Objects[objectID]; !ok {
			return false
		}
		for _, chunkID := range ids {
			chunk, ok := s.state.SemanticChunks[chunkID]
			if !ok {
				return false
			}
			if !validSemanticChunk(chunk, objectID, chunkID) {
				return false
			}
		}
	}

	for chunkID, chunk := range s.state.SemanticChunks {
		if !validSemanticChunk(chunk, chunk.ObjectID, chunkID) {
			return false
		}
		cp := semanticChunk{
			ID:          chunk.ID,
			ObjectID:    chunk.ObjectID,
			SectionID:   chunk.SectionID,
			SectionKind: chunk.SectionKind,
			Text:        chunk.Text,
			StartChar:   chunk.StartChar,
			EndChar:     chunk.EndChar,
			Vector:      append([]float32(nil), chunk.Vector...),
		}
		s.semanticChunks[chunkID] = cp
		s.annInsertBucketsOnlyLocked(chunkID, cp.Vector)
		s.indexChunkLexicalLocked(chunkID, cp)
	}
	for objectID, ids := range s.state.ObjectChunkIDs {
		s.objectChunkIDs[objectID] = append([]string(nil), ids...)
	}
	restoredFromSnapshot := false
	if s.annEngine != nil {
		if !s.restoreANNSnapshotLocked() {
			ids := make([]string, 0, len(s.semanticChunks))
			for chunkID := range s.semanticChunks {
				ids = append(ids, chunkID)
			}
			sort.Strings(ids)
			for _, chunkID := range ids {
				chunk := s.semanticChunks[chunkID]
				s.annUpsertEngineOnlyLocked(chunkID, chunk.Vector)
			}
		} else {
			restoredFromSnapshot = true
		}
	}
	if s.annEngine == nil {
		s.setANNInitStatusLocked("lsh_rebuilt_from_state", len(s.semanticChunks))
	} else if restoredFromSnapshot {
		s.setANNInitStatusLocked("hnsw_snapshot_restored", len(s.semanticChunks))
	} else {
		s.setANNInitStatusLocked("hnsw_rebuilt_from_state", len(s.semanticChunks))
	}
	return true
}

func validSemanticChunk(chunk semanticChunk, objectID, chunkID string) bool {
	if strings.TrimSpace(chunk.ID) == "" || strings.TrimSpace(chunk.ID) != strings.TrimSpace(chunkID) {
		return false
	}
	if strings.TrimSpace(chunk.ObjectID) == "" || strings.TrimSpace(chunk.ObjectID) != strings.TrimSpace(objectID) {
		return false
	}
	if strings.TrimSpace(chunk.Text) == "" {
		return false
	}
	if len(chunk.Vector) != semanticEmbeddingDims {
		return false
	}
	return true
}

func (s *vaultStore) rankObjectsHybridLocked(query, collection string) []rankedObject {
	query = strings.TrimSpace(query)
	collection = normalizeCollectionName(collection)
	if query == "" {
		return nil
	}

	lexical := rankFTSMatches(s.state.Objects, s.state.Order, s.index, query, collection)
	lexScoreByID := make(map[string]int, len(lexical))
	for _, row := range lexical {
		if row.score > lexScoreByID[row.id] {
			lexScoreByID[row.id] = row.score
		}
	}

	semanticByID, semanticAnchor := s.semanticObjectScoresLocked(query, collection)
	candidateIDs := make(map[string]struct{}, len(lexScoreByID)+len(semanticByID))
	for id := range lexScoreByID {
		candidateIDs[id] = struct{}{}
	}
	for id := range semanticByID {
		candidateIDs[id] = struct{}{}
	}

	orderPos := make(map[string]int, len(s.state.Order))
	for idx, id := range s.state.Order {
		orderPos[id] = idx
	}

	out := make([]rankedObject, 0, len(candidateIDs))
	for id := range candidateIDs {
		obj, ok := s.state.Objects[id]
		if !ok {
			continue
		}
		if collection != "" && normalizeCollectionName(obj.Collection) != collection {
			continue
		}
		if _, err := s.requireCollectionAccessLocked(obj.Collection); err != nil {
			continue
		}

		lex := float64(lexScoreByID[id])
		sem := semanticByID[id]
		if lex == 0 && (sem < semanticMinObjectScore || !semanticAnchor[id]) {
			continue
		}
		score := lex + (sem * semanticBoostWeight)
		out = append(out, rankedObject{
			id:    id,
			score: int(math.Round(score * 1000)),
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

func (s *vaultStore) selectSnippetForObjectLocked(obj vaultObject, query string, maxChars int) snippetSelection {
	query = strings.TrimSpace(query)
	objectSelection := selectSnippet(obj.Content, query, maxChars, s.retrieval)
	if query == "" {
		return objectSelection
	}
	chunk, ok := s.bestChunkForQueryLocked(obj.ID, query)
	if !ok {
		return objectSelection
	}
	chunkSelection := selectSnippet(chunk.Text, query, maxChars, s.retrieval)
	if chunkSelection.snippet == "" {
		return objectSelection
	}
	chunkSelection.startChar += chunk.StartChar
	chunkSelection.endChar += chunk.StartChar

	objectScore := scoreSnippetForQuery(objectSelection.snippet, query)
	chunkScore := scoreSnippetForQuery(chunkSelection.snippet, query)
	if chunkScore > objectScore+0.05 {
		return chunkSelection
	}
	return objectSelection
}

func (s *vaultStore) bestChunkForQueryLocked(objectID, query string) (semanticChunk, bool) {
	objectID = strings.TrimSpace(objectID)
	query = strings.TrimSpace(query)
	if objectID == "" || query == "" {
		return semanticChunk{}, false
	}
	chunkIDs := s.objectChunkIDs[objectID]
	if len(chunkIDs) == 0 {
		return semanticChunk{}, false
	}
	queryVec := s.embedTextLocked(query)
	queryTokens := tokenizeText(strings.ToLower(query))
	queryStems := stemSet(queryTokens)

	bestScore := 0.0
	var best semanticChunk
	for _, chunkID := range chunkIDs {
		chunk, ok := s.semanticChunks[chunkID]
		if !ok {
			continue
		}
		score := cosineSimilarity(queryVec, chunk.Vector)
		if containsAnyToken(chunk.Text, queryTokens) {
			score += 0.05
		}
		if hasStemOverlap(chunk.Text, queryStems) {
			score += 0.08
		}
		if score > bestScore {
			bestScore = score
			best = chunk
		}
	}
	if bestScore <= 0 {
		return semanticChunk{}, false
	}
	return best, true
}

func (s *vaultStore) semanticObjectScoresLocked(query, collection string) (map[string]float64, map[string]bool) {
	query = strings.TrimSpace(query)
	if query == "" || len(s.semanticChunks) == 0 {
		return map[string]float64{}, map[string]bool{}
	}
	collection = normalizeCollectionName(collection)
	queryVec := s.embedTextLocked(query)
	queryTokens := tokenizeText(strings.ToLower(query))
	queryStems := stemSet(queryTokens)
	candidateChunkIDs := s.annCandidateChunkIDsLocked(queryVec, semanticANNCandidateLimit)
	if len(candidateChunkIDs) == 0 {
		candidateChunkIDs = make([]string, 0, len(s.semanticChunks))
		for chunkID := range s.semanticChunks {
			candidateChunkIDs = append(candidateChunkIDs, chunkID)
		}
	}

	scores := map[string]float64{}
	anchor := map[string]bool{}
	for _, chunkID := range candidateChunkIDs {
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
		score := cosineSimilarity(queryVec, chunk.Vector)
		tokenAnchor := containsAnyToken(chunk.Text, queryTokens)
		stemAnchor := hasStemOverlap(chunk.Text, queryStems)
		if tokenAnchor {
			score += 0.05
		}
		if stemAnchor {
			score += 0.08
		}
		if score <= 0 {
			continue
		}
		if current, ok := scores[chunk.ObjectID]; !ok || score > current {
			scores[chunk.ObjectID] = score
		}
		if tokenAnchor || stemAnchor {
			anchor[chunk.ObjectID] = true
		}
	}
	return scores, anchor
}

func (s *vaultStore) indexObjectChunksLocked(obj vaultObject) {
	s.unindexObjectChunksLocked(obj.ID)
	content := strings.TrimSpace(obj.Content)
	if content == "" {
		return
	}
	sections := splitSemanticSections(obj)
	if len(sections) == 0 {
		return
	}
	if s.semanticChunks == nil {
		s.semanticChunks = map[string]semanticChunk{}
	}
	if s.objectChunkIDs == nil {
		s.objectChunkIDs = map[string][]string{}
	}
	if s.annBuckets == nil {
		s.annBuckets = map[uint64][]string{}
	}
	if s.chunkANNKeys == nil {
		s.chunkANNKeys = map[string][]uint64{}
	}
	ids := make([]string, 0, semanticMaxChunksPerObject)
	chunkOrdinal := 1
	for _, section := range sections {
		if len(ids) >= semanticMaxChunksPerObject {
			break
		}
		windows := chunkText(section.text, semanticChunkTargetChars, semanticChunkOverlapChars, semanticMaxChunksPerObject-len(ids))
		for _, window := range windows {
			chunkID := fmt.Sprintf("%s::chunk_%03d", obj.ID, chunkOrdinal)
			chunkOrdinal++
			embedding := s.embedTextLocked(joinForIndex(obj.Title, section.kind, window.text))
			chunk := semanticChunk{
				ID:          chunkID,
				ObjectID:    obj.ID,
				SectionID:   section.id,
				SectionKind: section.kind,
				Text:        window.text,
				StartChar:   section.startChar + window.startChar,
				EndChar:     section.startChar + window.endChar,
				Vector:      embedding,
			}
			s.semanticChunks[chunkID] = chunk
			s.annInsertChunkLocked(chunkID, embedding)
			s.indexChunkLexicalLocked(chunkID, chunk)
			ids = append(ids, chunkID)
			if len(ids) >= semanticMaxChunksPerObject {
				break
			}
		}
	}
	s.objectChunkIDs[obj.ID] = ids
}

func (s *vaultStore) unindexObjectChunksLocked(id string) {
	if s.semanticChunks == nil || s.objectChunkIDs == nil {
		return
	}
	chunkIDs := s.objectChunkIDs[id]
	for _, chunkID := range chunkIDs {
		s.annDeleteChunkLocked(chunkID)
		s.unindexChunkLexicalLocked(chunkID)
		delete(s.semanticChunks, chunkID)
	}
	delete(s.objectChunkIDs, id)
}

func chunkText(content string, targetChars, overlapChars, maxChunks int) []semanticWindow {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}
	if targetChars <= 0 {
		targetChars = semanticChunkTargetChars
	}
	if overlapChars < 0 {
		overlapChars = 0
	}
	if maxChunks <= 0 {
		maxChunks = semanticMaxChunksPerObject
	}
	if overlapChars >= targetChars {
		overlapChars = targetChars / 4
	}
	runes := []rune(content)
	if len(runes) == 0 {
		return nil
	}

	out := make([]semanticWindow, 0, minInt(maxChunks, 8))
	start := 0
	for start < len(runes) && len(out) < maxChunks {
		end := start + targetChars
		if end >= len(runes) {
			end = len(runes)
		} else {
			end = extendChunkBoundary(runes, start, end)
		}
		if end <= start {
			break
		}
		segment := normalizeSpacing(string(runes[start:end]))
		if segment != "" {
			out = append(out, semanticWindow{
				text:      segment,
				startChar: start,
				endChar:   end,
			})
		}
		if end >= len(runes) {
			break
		}
		nextStart := end - overlapChars
		if nextStart <= start {
			nextStart = end
		}
		start = nextStart
	}
	return out
}

func splitSemanticSections(obj vaultObject) []semanticSection {
	content := strings.TrimSpace(obj.Content)
	if content == "" {
		return nil
	}
	switch inferSemanticContentKind(obj) {
	case "repo":
		return splitRepoSections(obj.ID, content)
	case "email":
		return splitEmailSections(obj.ID, content)
	default:
		return splitDocumentSections(obj.ID, content)
	}
}

func inferSemanticContentKind(obj vaultObject) string {
	title := strings.ToLower(strings.TrimSpace(obj.Title))
	content := strings.ToLower(strings.TrimSpace(obj.Content))
	for _, ext := range []string{".go", ".py", ".js", ".ts", ".tsx", ".java", ".rb", ".rs", ".cpp", ".c", ".h"} {
		if strings.HasSuffix(title, ext) {
			return "repo"
		}
	}
	if strings.Count(content, "\nfunc ") >= 1 || strings.Count(content, "\nclass ") >= 1 || strings.Count(content, "\ndef ") >= 1 {
		return "repo"
	}
	if strings.Contains(content, "\nfrom:") || strings.Contains(content, "\nsubject:") || strings.Contains(content, "\non ") && strings.Contains(content, " wrote:") {
		return "email"
	}
	return "document"
}

func splitDocumentSections(objectID, content string) []semanticSection {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}
	blocks := splitBlocksWithOffsets(content, "\n\n")
	out := make([]semanticSection, 0, minInt(len(blocks), 32))
	for idx, block := range blocks {
		text := normalizeSpacing(block.text)
		if text == "" {
			continue
		}
		sectionID := fmt.Sprintf("%s::section_doc_%03d", objectID, idx+1)
		out = append(out, semanticSection{
			id:        sectionID,
			kind:      "document",
			text:      text,
			startChar: block.start,
			endChar:   block.end,
		})
	}
	if len(out) == 0 {
		return []semanticSection{{
			id:        fmt.Sprintf("%s::section_doc_001", objectID),
			kind:      "document",
			text:      normalizeSpacing(content),
			startChar: 0,
			endChar:   len([]rune(content)),
		}}
	}
	return out
}

func splitEmailSections(objectID, content string) []semanticSection {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	type boundary struct {
		line int
	}
	bounds := []boundary{{line: 0}}
	for idx, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "from:") && idx != 0 {
			bounds = append(bounds, boundary{line: idx})
			continue
		}
		if strings.HasPrefix(lower, "on ") && strings.Contains(lower, " wrote:") {
			bounds = append(bounds, boundary{line: idx})
		}
	}
	bounds = append(bounds, boundary{line: len(lines)})
	lineStarts := make([]int, len(lines)+1)
	runes := []rune(content)
	cursor := 0
	lineStarts[0] = 0
	for i, r := range runes {
		if r == '\n' {
			cursor++
			lineStarts[cursor] = i + 1
		}
	}
	lineStarts[len(lines)] = len(runes)

	out := make([]semanticSection, 0, minInt(len(bounds), 16))
	for idx := 0; idx+1 < len(bounds); idx++ {
		startLine := bounds[idx].line
		endLine := bounds[idx+1].line
		if startLine < 0 || startLine >= len(lineStarts) || endLine < 0 || endLine >= len(lineStarts) {
			continue
		}
		start := lineStarts[startLine]
		end := lineStarts[endLine]
		if end <= start {
			continue
		}
		sectionText := normalizeSpacing(string(runes[start:end]))
		if sectionText == "" {
			continue
		}
		out = append(out, semanticSection{
			id:        fmt.Sprintf("%s::section_email_%03d", objectID, idx+1),
			kind:      "email_message",
			text:      sectionText,
			startChar: start,
			endChar:   end,
		})
	}
	if len(out) == 0 {
		return splitDocumentSections(objectID, content)
	}
	return out
}

func splitRepoSections(objectID, content string) []semanticSection {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	symbolPrefixes := []string{"func ", "type ", "class ", "def ", "interface "}
	type boundary struct {
		line int
	}
	bounds := []boundary{{line: 0}}
	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		for _, prefix := range symbolPrefixes {
			if strings.HasPrefix(trimmed, prefix) && idx != 0 {
				bounds = append(bounds, boundary{line: idx})
				break
			}
		}
	}
	bounds = append(bounds, boundary{line: len(lines)})
	lineStarts := make([]int, len(lines)+1)
	runes := []rune(content)
	cursor := 0
	lineStarts[0] = 0
	for i, r := range runes {
		if r == '\n' {
			cursor++
			lineStarts[cursor] = i + 1
		}
	}
	lineStarts[len(lines)] = len(runes)

	out := make([]semanticSection, 0, minInt(len(bounds), 24))
	for idx := 0; idx+1 < len(bounds); idx++ {
		start := lineStarts[bounds[idx].line]
		end := lineStarts[bounds[idx+1].line]
		if end <= start {
			continue
		}
		section := normalizeSpacing(string(runes[start:end]))
		if section == "" {
			continue
		}
		out = append(out, semanticSection{
			id:        fmt.Sprintf("%s::section_repo_%03d", objectID, idx+1),
			kind:      "code_symbol",
			text:      section,
			startChar: start,
			endChar:   end,
		})
	}
	if len(out) == 0 {
		return splitDocumentSections(objectID, content)
	}
	return out
}

type textBlockOffset struct {
	text  string
	start int
	end   int
}

func splitBlocksWithOffsets(content, sep string) []textBlockOffset {
	if strings.TrimSpace(content) == "" {
		return nil
	}
	if sep == "" {
		return []textBlockOffset{{
			text:  content,
			start: 0,
			end:   len([]rune(content)),
		}}
	}
	runes := []rune(content)
	sepRunes := []rune(sep)
	if len(sepRunes) == 0 {
		return []textBlockOffset{{
			text:  content,
			start: 0,
			end:   len(runes),
		}}
	}
	out := make([]textBlockOffset, 0, 12)
	start := 0
	for i := 0; i <= len(runes)-len(sepRunes); i++ {
		if !runesMatch(runes[i:i+len(sepRunes)], sepRunes) {
			continue
		}
		if i > start {
			out = append(out, textBlockOffset{
				text:  string(runes[start:i]),
				start: start,
				end:   i,
			})
		}
		i += len(sepRunes) - 1
		start = i + 1
	}
	if start < len(runes) {
		out = append(out, textBlockOffset{
			text:  string(runes[start:]),
			start: start,
			end:   len(runes),
		})
	}
	return out
}

func runesMatch(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func extendChunkBoundary(runes []rune, start, end int) int {
	if end >= len(runes) {
		return len(runes)
	}
	maxLookahead := minInt(64, len(runes)-end)
	best := end
	for i := 0; i < maxLookahead; i++ {
		r := runes[end+i]
		if unicode.IsSpace(r) {
			return end + i
		}
		if r == '.' || r == ',' || r == ';' || r == ':' || r == ')' || r == ']' {
			best = end + i + 1
			break
		}
	}
	if best > end {
		return best
	}
	return end
}

func semanticEmbedding(text string) []float32 {
	features := semanticFeatures(text)
	vec := make([]float32, semanticEmbeddingDims)
	if len(features) == 0 {
		return vec
	}
	for _, feature := range features {
		h := hashFeature(feature)
		idxA := int(h % uint32(semanticEmbeddingDims))
		idxB := int(((h >> 16) ^ (h * 2654435761)) % uint32(semanticEmbeddingDims))
		signA := float32(1)
		if h&1 == 1 {
			signA = -1
		}
		signB := float32(1)
		if (h>>1)&1 == 1 {
			signB = -1
		}
		vec[idxA] += signA
		if idxB != idxA {
			vec[idxB] += 0.5 * signB
		}
	}
	normalizeVector(vec)
	return vec
}

func semanticFeatures(text string) []string {
	tokens := tokenizeText(strings.ToLower(strings.TrimSpace(text)))
	if len(tokens) == 0 {
		return nil
	}
	out := make([]string, 0, len(tokens)*6)
	for _, tok := range tokens {
		if len(tok) < 2 {
			continue
		}
		out = append(out, "t:"+tok)
		stem := stemToken(tok)
		if stem != tok && len(stem) >= 2 {
			out = append(out, "s:"+stem)
		}
		for _, gram := range tokenNGrams(tok, 3, 4, 10) {
			out = append(out, "g:"+gram)
		}
	}
	return out
}

func stemToken(token string) string {
	token = strings.TrimSpace(strings.ToLower(token))
	if len(token) <= 3 {
		return token
	}
	switch {
	case len(token) > 5 && strings.HasSuffix(token, "ization"):
		return strings.TrimSuffix(token, "ization")
	case len(token) > 5 && strings.HasSuffix(token, "ation"):
		return strings.TrimSuffix(token, "ation")
	case len(token) > 4 && strings.HasSuffix(token, "ing"):
		return strings.TrimSuffix(token, "ing")
	case len(token) > 4 && strings.HasSuffix(token, "ers"):
		return strings.TrimSuffix(token, "ers")
	case len(token) > 4 && strings.HasSuffix(token, "ies"):
		return strings.TrimSuffix(token, "ies") + "y"
	case len(token) > 4 && strings.HasSuffix(token, "ied"):
		return strings.TrimSuffix(token, "ied") + "y"
	case len(token) > 3 && strings.HasSuffix(token, "ed"):
		return strings.TrimSuffix(token, "ed")
	case len(token) > 3 && strings.HasSuffix(token, "es"):
		return strings.TrimSuffix(token, "es")
	case len(token) > 3 && strings.HasSuffix(token, "s"):
		return strings.TrimSuffix(token, "s")
	default:
		return token
	}
}

func tokenNGrams(token string, minN, maxN, maxPerToken int) []string {
	runes := []rune(token)
	if len(runes) == 0 || minN <= 0 || maxN < minN || maxPerToken <= 0 {
		return nil
	}
	out := make([]string, 0, maxPerToken)
	for n := minN; n <= maxN; n++ {
		if len(runes) < n {
			continue
		}
		for i := 0; i+n <= len(runes); i++ {
			out = append(out, string(runes[i:i+n]))
			if len(out) >= maxPerToken {
				return out
			}
		}
	}
	return out
}

func stemSet(tokens []string) map[string]struct{} {
	if len(tokens) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(tokens))
	for _, tok := range tokens {
		stem := stemToken(tok)
		if len(stem) < 2 {
			continue
		}
		out[stem] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func hasStemOverlap(content string, queryStems map[string]struct{}) bool {
	if len(queryStems) == 0 {
		return false
	}
	tokens := tokenizeText(strings.ToLower(content))
	for _, tok := range tokens {
		stem := stemToken(tok)
		if _, ok := queryStems[stem]; ok {
			return true
		}
	}
	return false
}

func (s *vaultStore) annInsertChunkLocked(chunkID string, vec []float32) {
	if len(vec) == 0 {
		return
	}
	s.annUpsertEngineOnlyLocked(chunkID, vec)
	s.annInsertBucketsOnlyLocked(chunkID, vec)
}

func (s *vaultStore) annDeleteChunkLocked(chunkID string) {
	if s.annEngine != nil {
		_ = s.annEngine.Delete(chunkID)
	}
	if s.annBuckets == nil || s.chunkANNKeys == nil {
		return
	}
	keys := s.chunkANNKeys[chunkID]
	for _, key := range keys {
		bucket := s.annBuckets[key]
		if len(bucket) == 0 {
			continue
		}
		filtered := bucket[:0]
		for _, current := range bucket {
			if current == chunkID {
				continue
			}
			filtered = append(filtered, current)
		}
		if len(filtered) == 0 {
			delete(s.annBuckets, key)
			continue
		}
		s.annBuckets[key] = append([]string(nil), filtered...)
	}
	delete(s.chunkANNKeys, chunkID)
}

func (s *vaultStore) annUpsertEngineOnlyLocked(chunkID string, vec []float32) {
	if len(vec) == 0 || s.annEngine == nil {
		return
	}
	if err := s.annEngine.Upsert(chunkID, vec); err != nil {
		s.annEngine.Close()
		s.annEngine = nil
		s.retrieval.indexMeta.ANNVersion = "lsh.ann.v1"
	}
}

func (s *vaultStore) annInsertBucketsOnlyLocked(chunkID string, vec []float32) {
	if len(vec) == 0 {
		return
	}
	if s.annBuckets == nil {
		s.annBuckets = map[uint64][]string{}
	}
	if s.chunkANNKeys == nil {
		s.chunkANNKeys = map[string][]uint64{}
	}
	keys := annBucketKeys(vec)
	for _, key := range keys {
		bucket := s.annBuckets[key]
		if containsString(bucket, chunkID) {
			continue
		}
		s.annBuckets[key] = append(bucket, chunkID)
	}
	s.chunkANNKeys[chunkID] = append([]uint64(nil), keys...)
}

func (s *vaultStore) annCandidateChunkIDsLocked(queryVec []float32, limit int) []string {
	if len(queryVec) == 0 || limit <= 0 {
		return nil
	}
	if s.annEngine != nil {
		if ids, err := s.annEngine.Query(queryVec, limit); err == nil && len(ids) > 0 {
			if len(ids) >= limit {
				return ids[:limit]
			}
			// Top up with deterministic bucket candidates when ANN returns fewer rows.
			seen := make(map[string]struct{}, len(ids))
			for _, id := range ids {
				id = strings.TrimSpace(id)
				if id == "" {
					continue
				}
				seen[id] = struct{}{}
			}
			extra := s.annCandidateChunkIDsFromBucketsLocked(queryVec, limit-len(ids), seen)
			if len(extra) == 0 {
				return ids
			}
			return append(ids, extra...)
		}
	}
	return s.annCandidateChunkIDsFromBucketsLocked(queryVec, limit, nil)
}

func (s *vaultStore) annCandidateChunkIDsFromBucketsLocked(queryVec []float32, limit int, excluded map[string]struct{}) []string {
	if len(queryVec) == 0 || limit <= 0 {
		return nil
	}
	if len(s.annBuckets) == 0 {
		return nil
	}
	keys := annBucketKeys(queryVec)
	if len(keys) == 0 {
		return nil
	}
	hits := map[string]int{}
	for _, key := range keys {
		for _, chunkID := range s.annBuckets[key] {
			chunkID = strings.TrimSpace(chunkID)
			if chunkID == "" {
				continue
			}
			if excluded != nil {
				if _, skip := excluded[chunkID]; skip {
					continue
				}
			}
			hits[chunkID]++
		}
	}
	if len(hits) == 0 {
		return nil
	}
	type candidate struct {
		id   string
		hits int
	}
	rows := make([]candidate, 0, len(hits))
	for id, count := range hits {
		rows = append(rows, candidate{id: id, hits: count})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].hits != rows[j].hits {
			return rows[i].hits > rows[j].hits
		}
		return rows[i].id < rows[j].id
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.id)
	}
	return out
}

func annBucketKeys(vec []float32) []uint64 {
	if len(vec) == 0 {
		return nil
	}
	keys := make([]uint64, 0, semanticANNTables)
	for table := 0; table < semanticANNTables; table++ {
		bits := uint64(0)
		for bit := 0; bit < semanticANNBits; bit++ {
			if annBit(vec, table, bit) {
				bits |= uint64(1) << uint(bit)
			}
		}
		key := (uint64(table) << 56) | bits
		keys = append(keys, key)
	}
	return keys
}

func annBit(vec []float32, table, bit int) bool {
	dims := len(vec)
	if dims == 0 {
		return false
	}
	idxA := (table*29 + bit*17 + 13) % dims
	idxB := (table*43 + bit*23 + 7) % dims
	weightA := float64(((table+1)*(bit+3))%5 + 1)
	weightB := float64(((table+2)*(bit+5))%7 + 1)
	score := float64(vec[idxA])*weightA - float64(vec[idxB])*weightB
	return score >= 0
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func hashFeature(feature string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(feature))
	return h.Sum32()
}

func normalizeVector(vec []float32) {
	var norm float64
	for _, v := range vec {
		norm += float64(v * v)
	}
	if norm == 0 {
		return
	}
	inv := 1.0 / math.Sqrt(norm)
	for i := range vec {
		vec[i] = float32(float64(vec[i]) * inv)
	}
}

func cosineSimilarity(a, b []float32) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	n := minInt(len(a), len(b))
	sum := 0.0
	for i := 0; i < n; i++ {
		sum += float64(a[i] * b[i])
	}
	return sum
}

func (s *vaultStore) embedTextLocked(text string) []float32 {
	raw := truncateUTF8ByBytes(normalizeSpacing(text), 12000)
	if raw == "" {
		return semanticEmbedding("")
	}
	key := s.normalizeQueryKeyLocked(raw)
	if s.embeddingCache == nil {
		s.embeddingCache = map[string][]float32{}
	}
	if s.embeddingCacheAt == nil {
		s.embeddingCacheAt = map[string]time.Time{}
	}
	if cached, ok := s.embeddingCache[key]; ok && len(cached) == semanticEmbeddingDims {
		if ts, okTS := s.embeddingCacheAt[key]; !okTS || s.retrieval.cacheTTL <= 0 || time.Since(ts) <= s.retrieval.cacheTTL {
			return append([]float32(nil), cached...)
		}
		delete(s.embeddingCache, key)
		delete(s.embeddingCacheAt, key)
	}

	vec := semanticEmbedding(raw)
	if s.retrieval.embedder != nil {
		embedded, err := s.retrieval.embedder.Embed(context.Background(), raw)
		if err == nil && len(embedded) > 0 {
			proj := projectEmbedding(embedded, semanticEmbeddingDims)
			if len(proj) == semanticEmbeddingDims {
				// Blend deterministic + model embedding for stable fallback behavior.
				for i := range proj {
					vec[i] = (vec[i] * 0.25) + (proj[i] * 0.75)
				}
				normalizeVector(vec)
			}
		}
	}
	if len(s.embeddingCache) >= s.retrieval.maxCacheEntries {
		s.embeddingCache = map[string][]float32{}
		s.embeddingCacheAt = map[string]time.Time{}
	}
	s.embeddingCache[key] = append([]float32(nil), vec...)
	s.embeddingCacheAt[key] = time.Now()
	return vec
}

func (s *vaultStore) normalizeQueryKeyLocked(v string) string {
	if s == nil {
		return normalizeSpacing(strings.ToLower(v))
	}
	v = normalizeSpacing(strings.ToLower(v))
	if v == "" {
		return ""
	}
	if s.queryNormCache == nil {
		s.queryNormCache = map[string]string{}
	}
	if cached, ok := s.queryNormCache[v]; ok {
		return cached
	}
	if len(s.queryNormCache) >= s.retrieval.maxCacheEntries {
		s.queryNormCache = map[string]string{}
	}
	s.queryNormCache[v] = v
	return v
}

func (s *vaultStore) semanticIndexMetaCompatibleLocked() bool {
	if s == nil || s.state == nil {
		return false
	}
	want := s.retrieval.indexMeta
	got := s.state.IndexMeta
	if strings.TrimSpace(got.Version) == "" {
		return false
	}
	return got.Version == want.Version &&
		got.EmbeddingBackend == want.EmbeddingBackend &&
		got.EmbeddingModel == want.EmbeddingModel &&
		got.EmbeddingDim == want.EmbeddingDim &&
		got.ChunkingVersion == want.ChunkingVersion &&
		got.LexicalIndexVersion == want.LexicalIndexVersion &&
		got.ANNVersion == want.ANNVersion &&
		got.HNSWM == want.HNSWM &&
		got.HNSWEfConstruction == want.HNSWEfConstruction &&
		got.RerankerVersion == want.RerankerVersion
}
