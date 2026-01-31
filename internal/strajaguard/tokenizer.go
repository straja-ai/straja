package strajaguard

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

type Tokenizer interface {
	Encode(text string, seqLen int) ([]int64, []int64)
}

type OffsetTokenizer interface {
	Tokenizer
	EncodeWithOffsets(text string, seqLen int) ([]int64, []int64, []tokenOffset)
}

type specialTokenMeta struct {
	IDs []int64 `json:"ids"`
}

// WordPieceTokenizer implements a minimal DistilBERT-compatible tokenizer.
type WordPieceTokenizer struct {
	vocab        map[string]int64
	lowerCase    bool
	clsID        int64
	sepID        int64
	padID        int64
	unkID        int64
	continuation string
}

type UnigramTokenizer struct {
	vocab        map[string]int64
	scores       []float64
	unkID        int64
	unkScore     float64
	byteFallback bool
	byteTokens   map[byte]int64
	clsID        int64
	sepID        int64
	padID        int64
	trie         *unigramTrie
}

// LoadWordPieceTokenizer builds the tokenizer from vocab.txt.
func LoadWordPieceTokenizer(path string) (*WordPieceTokenizer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open vocab: %w", err)
	}
	defer f.Close()

	vocab := make(map[string]int64)
	sc := bufio.NewScanner(f)
	var idx int64
	for sc.Scan() {
		token := strings.TrimSpace(sc.Text())
		if token == "" {
			continue
		}
		vocab[token] = idx
		idx++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan vocab: %w", err)
	}

	t := &WordPieceTokenizer{
		vocab:        vocab,
		lowerCase:    true,
		continuation: "##",
		clsID:        vocab["[CLS]"],
		sepID:        vocab["[SEP]"],
		padID:        vocab["[PAD]"],
		unkID:        vocab["[UNK]"],
	}
	return t, nil
}

// LoadTokenizerFromDir loads a tokenizer from vocab.txt or tokenizer.json.
func LoadTokenizerFromDir(dir string) (Tokenizer, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("tokenizer dir is empty")
	}
	candidates := []string{
		filepath.Join(dir, "vocab.txt"),
		filepath.Join(dir, "tokenizer", "vocab.txt"),
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return LoadWordPieceTokenizer(path)
		}
	}

	jsonCandidates := []string{
		filepath.Join(dir, "tokenizer.json"),
		filepath.Join(dir, "tokenizer", "tokenizer.json"),
	}
	for _, path := range jsonCandidates {
		if _, err := os.Stat(path); err == nil {
			return loadTokenizerFromJSON(path)
		}
	}
	return nil, fmt.Errorf("tokenizer assets not found (vocab.txt or tokenizer.json)")
}

func loadTokenizerFromJSON(path string) (Tokenizer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tokenizer.json: %w", err)
	}
	var raw struct {
		Model struct {
			Type         string `json:"type"`
			Vocab        any    `json:"vocab"`
			UnkID        int    `json:"unk_id"`
			ByteFallback bool   `json:"byte_fallback"`
		} `json:"model"`
		PostProcessor struct {
			SpecialTokens map[string]specialTokenMeta `json:"special_tokens"`
		} `json:"post_processor"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode tokenizer.json: %w", err)
	}
	modelType := strings.ToLower(strings.TrimSpace(raw.Model.Type))
	if modelType == "unigram" {
		tokens, scores, vocabMap := vocabWithScores(raw.Model.Vocab)
		if len(tokens) == 0 {
			return nil, fmt.Errorf("tokenizer.json missing vocab")
		}
		clsID := pickSpecialID(vocabMap, raw.PostProcessor.SpecialTokens, "[CLS]")
		sepID := pickSpecialID(vocabMap, raw.PostProcessor.SpecialTokens, "[SEP]")
		padID := pickSpecialID(vocabMap, raw.PostProcessor.SpecialTokens, "[PAD]")
		tok := newUnigramTokenizer(tokens, scores, vocabMap, raw.Model.UnkID, raw.Model.ByteFallback, clsID, sepID, padID)
		return tok, nil
	}

	if vocab := vocabFromAny(raw.Model.Vocab); len(vocab) > 0 {
		return newTokenizerFromVocab(vocab), nil
	}

	return nil, fmt.Errorf("tokenizer.json missing vocab")
}

func newTokenizerFromVocab(vocab map[string]int64) *WordPieceTokenizer {
	return &WordPieceTokenizer{
		vocab:        vocab,
		lowerCase:    true,
		continuation: "##",
		clsID:        vocab["[CLS]"],
		sepID:        vocab["[SEP]"],
		padID:        vocab["[PAD]"],
		unkID:        vocab["[UNK]"],
	}
}

func vocabWithScores(raw any) ([]string, []float64, map[string]int64) {
	switch v := raw.(type) {
	case []any:
		tokens := make([]string, 0, len(v))
		scores := make([]float64, 0, len(v))
		vocab := make(map[string]int64, len(v))
		for i, item := range v {
			pair, ok := item.([]any)
			if !ok || len(pair) < 2 {
				continue
			}
			token, ok := pair[0].(string)
			if !ok || token == "" {
				continue
			}
			score, ok := asFloat(pair[1])
			if !ok {
				continue
			}
			tokens = append(tokens, token)
			scores = append(scores, score)
			vocab[token] = int64(i)
		}
		return tokens, scores, vocab
	case map[string]any:
		vocab := make(map[string]int64, len(v))
		for k, val := range v {
			if num, ok := asInt64(val); ok {
				vocab[k] = num
			}
		}
		return nil, nil, vocab
	default:
		return nil, nil, nil
	}
}

func asFloat(v any) (float64, bool) {
	switch num := v.(type) {
	case float64:
		return num, true
	case float32:
		return float64(num), true
	case int:
		return float64(num), true
	case int64:
		return float64(num), true
	default:
		return 0, false
	}
}

func pickSpecialID(vocab map[string]int64, specials map[string]specialTokenMeta, token string) int64 {
	if specials != nil {
		if meta, ok := specials[token]; ok && len(meta.IDs) > 0 {
			return meta.IDs[0]
		}
	}
	if vocab != nil {
		if id, ok := vocab[token]; ok {
			return id
		}
	}
	return -1
}

func vocabFromAny(raw any) map[string]int64 {
	switch v := raw.(type) {
	case map[string]any:
		out := make(map[string]int64, len(v))
		for k, val := range v {
			if num, ok := asInt64(val); ok {
				out[k] = num
			}
		}
		return out
	case map[string]int64:
		return v
	case []any:
		out := make(map[string]int64, len(v))
		for i, item := range v {
			switch pair := item.(type) {
			case []any:
				if len(pair) == 0 {
					continue
				}
				token, ok := pair[0].(string)
				if !ok || token == "" {
					continue
				}
				out[token] = int64(i)
			case map[string]any:
				token, ok := pair["token"].(string)
				if !ok || token == "" {
					continue
				}
				if num, ok := asInt64(pair["id"]); ok {
					out[token] = num
				} else {
					out[token] = int64(i)
				}
			}
		}
		return out
	default:
		return nil
	}
}

func asInt64(v any) (int64, bool) {
	switch num := v.(type) {
	case float64:
		return int64(num), true
	case int64:
		return num, true
	case int:
		return int64(num), true
	default:
		return 0, false
	}
}

// Encode converts text into token IDs and an attention mask of length seqLen.
func (t *WordPieceTokenizer) Encode(text string, seqLen int) ([]int64, []int64) {
	if seqLen <= 0 {
		return nil, nil
	}

	words := strings.Fields(text)
	tokens := []int64{t.clsID}

	for _, w := range words {
		if t.lowerCase {
			w = strings.ToLower(w)
		}
		pieces := t.wordPiece(w)
		tokens = append(tokens, pieces...)
		if len(tokens) >= seqLen-1 {
			break
		}
	}
	tokens = append(tokens, t.sepID)

	if len(tokens) > seqLen {
		tokens = tokens[len(tokens)-seqLen:]
		if tokens[0] != t.clsID && t.clsID != 0 {
			tokens[0] = t.clsID
		}
	}

	attn := make([]int64, seqLen)
	for i := 0; i < len(tokens) && i < seqLen; i++ {
		attn[i] = 1
	}

	if len(tokens) < seqLen {
		pad := make([]int64, seqLen-len(tokens))
		for i := range pad {
			pad[i] = t.padID
		}
		tokens = append(tokens, pad...)
	}

	return tokens, attn
}

func (t *WordPieceTokenizer) wordPiece(token string) []int64 {
	if _, ok := t.vocab[token]; ok {
		return []int64{t.vocab[token]}
	}

	var pieces []int64
	start := 0
	for start < len(token) {
		end := len(token)
		var cur string
		for end > start {
			sub := token[start:end]
			if start > 0 {
				sub = t.continuation + sub
			}
			if id, ok := t.vocab[sub]; ok {
				cur = sub
				pieces = append(pieces, id)
				start = end
				break
			}
			end--
		}
		if cur == "" {
			return []int64{t.unkID}
		}
	}
	if len(pieces) == 0 {
		return []int64{t.unkID}
	}
	return pieces
}

type tokenOffset struct {
	Start int
	End   int
}

type wordSpan struct {
	Text  string
	Start int
	End   int
}

// EncodeWithOffsets converts text into token IDs/attention mask and offset mappings.
func (t *WordPieceTokenizer) EncodeWithOffsets(text string, seqLen int) ([]int64, []int64, []tokenOffset) {
	if seqLen <= 0 {
		return nil, nil, nil
	}

	words := splitWordsWithOffsets(text)
	tokens := []int64{t.clsID}
	offsets := []tokenOffset{{Start: -1, End: -1}}

	for _, w := range words {
		token := w.Text
		if t.lowerCase {
			token = strings.ToLower(token)
		}
		pieces := t.wordPieceOffsets(token)
		for _, p := range pieces {
			tokens = append(tokens, p.id)
			offsets = append(offsets, tokenOffset{
				Start: w.Start + p.start,
				End:   w.Start + p.end,
			})
			if len(tokens) >= seqLen-1 {
				break
			}
		}
		if len(tokens) >= seqLen-1 {
			break
		}
	}

	tokens = append(tokens, t.sepID)
	offsets = append(offsets, tokenOffset{Start: -1, End: -1})

	if len(tokens) > seqLen {
		tokens = tokens[len(tokens)-seqLen:]
		offsets = offsets[len(offsets)-seqLen:]
		if tokens[0] != t.clsID && t.clsID != 0 {
			tokens[0] = t.clsID
			offsets[0] = tokenOffset{Start: -1, End: -1}
		}
	}

	attn := make([]int64, seqLen)
	for i := 0; i < len(tokens) && i < seqLen; i++ {
		attn[i] = 1
	}

	if len(tokens) < seqLen {
		pad := make([]int64, seqLen-len(tokens))
		for i := range pad {
			pad[i] = t.padID
		}
		tokens = append(tokens, pad...)
		for len(offsets) < seqLen {
			offsets = append(offsets, tokenOffset{Start: -1, End: -1})
		}
	}

	return tokens, attn, offsets
}

type wordPieceOffset struct {
	id    int64
	start int
	end   int
}

func (t *WordPieceTokenizer) wordPieceOffsets(token string) []wordPieceOffset {
	if id, ok := t.vocab[token]; ok {
		return []wordPieceOffset{{id: id, start: 0, end: len(token)}}
	}

	var pieces []wordPieceOffset
	start := 0
	for start < len(token) {
		end := len(token)
		var cur string
		var curID int64
		for end > start {
			sub := token[start:end]
			if start > 0 {
				sub = t.continuation + sub
			}
			if id, ok := t.vocab[sub]; ok {
				cur = sub
				curID = id
				pieces = append(pieces, wordPieceOffset{id: curID, start: start, end: end})
				start = end
				break
			}
			end--
		}
		if cur == "" {
			return []wordPieceOffset{{id: t.unkID, start: 0, end: len(token)}}
		}
	}
	if len(pieces) == 0 {
		return []wordPieceOffset{{id: t.unkID, start: 0, end: len(token)}}
	}
	return pieces
}

func splitWordsWithOffsets(text string) []wordSpan {
	if text == "" {
		return nil
	}
	var spans []wordSpan
	start := -1
	for idx, r := range text {
		if unicode.IsSpace(r) {
			if start >= 0 {
				spans = append(spans, wordSpan{
					Text:  text[start:idx],
					Start: start,
					End:   idx,
				})
				start = -1
			}
			continue
		}
		if start < 0 {
			start = idx
		}
	}
	if start >= 0 {
		spans = append(spans, wordSpan{
			Text:  text[start:],
			Start: start,
			End:   len(text),
		})
	}
	return spans
}

type unigramTrie struct {
	children map[byte]*unigramTrie
	tokenID  int64
	score    float64
}

func newUnigramTokenizer(tokens []string, scores []float64, vocab map[string]int64, unkID int, byteFallback bool, clsID, sepID, padID int64) *UnigramTokenizer {
	t := &UnigramTokenizer{
		vocab:        vocab,
		scores:       scores,
		unkID:        int64(unkID),
		byteFallback: byteFallback,
		clsID:        clsID,
		sepID:        sepID,
		padID:        padID,
		trie:         &unigramTrie{children: map[byte]*unigramTrie{}, tokenID: -1},
	}
	t.byteTokens = t.collectByteTokens()
	if t.unkID >= 0 && int(t.unkID) < len(t.scores) {
		t.unkScore = t.scores[t.unkID]
	}
	for id, tok := range tokens {
		t.insertToken(tok, int64(id))
	}
	return t
}

func (t *UnigramTokenizer) insertToken(token string, id int64) {
	if t.trie == nil {
		return
	}
	node := t.trie
	for i := 0; i < len(token); i++ {
		b := token[i]
		if node.children == nil {
			node.children = make(map[byte]*unigramTrie)
		}
		child := node.children[b]
		if child == nil {
			child = &unigramTrie{tokenID: -1}
			node.children[b] = child
		}
		node = child
	}
	node.tokenID = id
	if int(id) < len(t.scores) {
		node.score = t.scores[id]
	}
}

func (t *UnigramTokenizer) collectByteTokens() map[byte]int64 {
	out := map[byte]int64{}
	if t.vocab == nil {
		return out
	}
	for tok, id := range t.vocab {
		if len(tok) == 6 && strings.HasPrefix(tok, "<0x") && strings.HasSuffix(tok, ">") {
			hex := tok[3:5]
			var b byte
			if n, err := fmt.Sscanf(hex, "%02X", &b); err == nil && n == 1 {
				out[b] = id
			}
		}
	}
	return out
}

func (t *UnigramTokenizer) Encode(text string, seqLen int) ([]int64, []int64) {
	if seqLen <= 0 {
		return nil, nil
	}
	tokenIDs := t.tokenize(text)
	ids := make([]int64, seqLen)
	attn := make([]int64, seqLen)
	pos := 0
	if t.clsID >= 0 && pos < seqLen {
		ids[pos] = t.clsID
		attn[pos] = 1
		pos++
	}
	for _, id := range tokenIDs {
		if pos >= seqLen {
			break
		}
		ids[pos] = id
		attn[pos] = 1
		pos++
	}
	if t.sepID >= 0 && pos < seqLen {
		ids[pos] = t.sepID
		attn[pos] = 1
		pos++
	}
	pad := t.padID
	if pad < 0 {
		pad = 0
	}
	for pos < seqLen {
		ids[pos] = pad
		pos++
	}
	return ids, attn
}

var collapseWhitespace = regexp.MustCompile(`\s+`)

func (t *UnigramTokenizer) normalize(text string) string {
	s := strings.TrimSpace(text)
	if s == "" {
		return ""
	}
	s = collapseWhitespace.ReplaceAllString(s, " ")
	return s
}

func (t *UnigramTokenizer) metaspace(text string) string {
	if text == "" {
		return ""
	}
	s := strings.ReplaceAll(text, " ", "▁")
	if !strings.HasPrefix(s, "▁") {
		s = "▁" + s
	}
	return s
}

func (t *UnigramTokenizer) tokenize(text string) []int64 {
	s := t.normalize(text)
	if s == "" {
		return nil
	}
	s = t.metaspace(s)
	input := []byte(s)
	n := len(input)
	dp := make([]float64, n+1)
	prev := make([]int, n+1)
	prevTok := make([]int64, n+1)
	for i := 1; i <= n; i++ {
		dp[i] = math.Inf(-1)
		prev[i] = -1
	}
	dp[0] = 0
	for i := 0; i < n; i++ {
		if math.IsInf(dp[i], -1) {
			continue
		}
		node := t.trie
		matched := false
		for j := i; j < n; j++ {
			if node == nil {
				break
			}
			node = node.children[input[j]]
			if node == nil {
				break
			}
			if node.tokenID >= 0 {
				matched = true
				score := dp[i] + node.score
				if score > dp[j+1] {
					dp[j+1] = score
					prev[j+1] = i
					prevTok[j+1] = node.tokenID
				}
			}
		}
		if matched {
			continue
		}
		if t.byteFallback {
			if id, ok := t.byteTokens[input[i]]; ok {
				score := dp[i] + t.scoreFor(id)
				if score > dp[i+1] {
					dp[i+1] = score
					prev[i+1] = i
					prevTok[i+1] = id
				}
				continue
			}
		}
		if t.unkID >= 0 {
			score := dp[i] + t.unkScore
			if score > dp[i+1] {
				dp[i+1] = score
				prev[i+1] = i
				prevTok[i+1] = t.unkID
			}
		}
	}
	if math.IsInf(dp[n], -1) {
		return nil
	}
	out := make([]int64, 0, n)
	for pos := n; pos > 0; {
		p := prev[pos]
		if p < 0 || p >= pos {
			out = append(out, t.unkID)
			pos--
			continue
		}
		out = append(out, prevTok[pos])
		pos = p
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (t *UnigramTokenizer) scoreFor(id int64) float64 {
	if id >= 0 && int(id) < len(t.scores) {
		return t.scores[id]
	}
	return 0
}
