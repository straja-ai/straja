package strajaguard

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// BPETokenizer implements a minimal byte-level BPE tokenizer compatible with
// HuggingFace tokenizers.json "BPE" model type.
//
// This implementation is intentionally narrow:
// - byte-level pre-tokenization using GPT-2 regex
// - merge ranks from tokenizer.json model.merges
// - special/added tokens are preserved as single tokens when present
//
// It is designed for deterministic, CPU-only inference on the gateway.
type BPETokenizer struct {
	vocab        map[string]int64
	mergeRanks   map[string]int
	unkID        int64
	padID        int64
	special      []string          // sorted by length desc for greedy matching
	specialIDs   map[string]int64
	encodeRe     *regexp.Regexp
	byteEncoder  map[byte]rune
	cache        map[string][]string
}

func (t *BPETokenizer) VocabSize() int {
	return len(t.vocab)
}

func newBPETokenizer(vocab map[string]int64, merges []string, unkID int64, padID int64, specialIDs map[string]int64) (*BPETokenizer, error) {
	if len(vocab) == 0 {
		return nil, fmt.Errorf("empty vocab")
	}
	mergeRanks := make(map[string]int, len(merges))
	for i, m := range merges {
		m = strings.TrimSpace(m)
		if m == "" || strings.HasPrefix(m, "#") {
			continue
		}
		parts := strings.SplitN(m, " ", 2)
		if len(parts) != 2 {
			continue
		}
		a := strings.TrimSpace(parts[0])
		b := strings.TrimSpace(parts[1])
		if a == "" || b == "" {
			continue
		}
		mergeRanks[a+"\x00"+b] = i
	}

	// GPT-2 regex used by ByteLevel pre-tokenizer, adapted for Go's regexp engine.
	// Go does not support lookaheads (e.g. (?!\S)), so we omit the trailing-space-only branch.
	// This is sufficient for deterministic tokenization for our classifier use case.
	encodeRe, err := regexp.Compile(`'s|'t|'re|'ve|'m|'ll|'d| ?\p{L}+| ?\p{N}+| ?[^\s\p{L}\p{N}]+|\s+`)
	if err != nil {
		return nil, err
	}

	special := make([]string, 0, len(specialIDs))
	for tok := range specialIDs {
		if tok == "" {
			continue
		}
		special = append(special, tok)
	}
	sort.Slice(special, func(i, j int) bool {
		if len(special[i]) == len(special[j]) {
			return special[i] < special[j]
		}
		return len(special[i]) > len(special[j])
	})

	if padID < 0 {
		// Best-effort default; many tokenizers include a pad token, but not all do.
		if id, ok := vocab["<|pad|>"]; ok {
			padID = id
		} else if id, ok := vocab["[PAD]"]; ok {
			padID = id
		} else if id, ok := vocab["<pad>"]; ok {
			padID = id
		} else {
			padID = 0
		}
	}

	return &BPETokenizer{
		vocab:       vocab,
		mergeRanks:  mergeRanks,
		unkID:       unkID,
		padID:       padID,
		special:     special,
		specialIDs:  specialIDs,
		encodeRe:    encodeRe,
		byteEncoder: bytesToUnicode(),
		cache:       make(map[string][]string),
	}, nil
}

func (t *BPETokenizer) Encode(text string, seqLen int) ([]int64, []int64) {
	if seqLen <= 0 {
		seqLen = 256
	}
	ids := make([]int64, 0, seqLen)

	parts := t.splitSpecial(text)
	for _, part := range parts {
		if part == "" {
			continue
		}
		if id, ok := t.specialIDs[part]; ok {
			ids = append(ids, id)
			continue
		}
		matches := t.encodeRe.FindAllString(part, -1)
		for _, m := range matches {
			if m == "" {
				continue
			}
			encoded := t.byteEncode(m)
			for _, tok := range t.bpe(encoded) {
				if id, ok := t.vocab[tok]; ok {
					ids = append(ids, id)
				} else {
					ids = append(ids, t.unkID)
				}
			}
		}
	}

	if len(ids) > seqLen {
		ids = ids[:seqLen]
	}
	attn := make([]int64, seqLen)
	outIDs := make([]int64, seqLen)
	for i := 0; i < seqLen; i++ {
		if i < len(ids) {
			outIDs[i] = ids[i]
			attn[i] = 1
		} else {
			outIDs[i] = t.padID
			attn[i] = 0
		}
	}
	return outIDs, attn
}

func (t *BPETokenizer) splitSpecial(s string) []string {
	if len(t.special) == 0 || s == "" {
		return []string{s}
	}
	out := make([]string, 0, 8)
	for len(s) > 0 {
		found := ""
		for _, tok := range t.special {
			if strings.HasPrefix(s, tok) {
				found = tok
				break
			}
		}
		if found != "" {
			out = append(out, found)
			s = s[len(found):]
			continue
		}

		// Consume up to the next special token occurrence.
		next := len(s)
		for _, tok := range t.special {
			if idx := strings.Index(s, tok); idx >= 0 && idx < next {
				next = idx
			}
		}
		out = append(out, s[:next])
		s = s[next:]
	}
	return out
}

func (t *BPETokenizer) byteEncode(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		r, ok := t.byteEncoder[s[i]]
		if !ok {
			// Shouldn't happen: mapping covers all 256 bytes.
			r = rune(s[i])
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (t *BPETokenizer) bpe(token string) []string {
	if token == "" {
		return nil
	}
	orig := token
	if cached, ok := t.cache[token]; ok {
		return cached
	}
	// Start with one symbol per rune.
	syms := make([]string, 0, utf8.RuneCountInString(token))
	for len(token) > 0 {
		r, size := utf8.DecodeRuneInString(token)
		if r == utf8.RuneError && size == 1 {
			// Invalid rune; treat as a byte.
			syms = append(syms, token[:1])
			token = token[1:]
			continue
		}
		syms = append(syms, string(r))
		token = token[size:]
	}

	if len(syms) == 1 {
		t.cache[orig] = syms
		return syms
	}

	for {
		bestRank := int(^uint(0) >> 1)
		bestIdx := -1
		for i := 0; i < len(syms)-1; i++ {
			key := syms[i] + "\x00" + syms[i+1]
			if rank, ok := t.mergeRanks[key]; ok && rank < bestRank {
				bestRank = rank
				bestIdx = i
			}
		}
		if bestIdx < 0 {
			break
		}
		merged := syms[bestIdx] + syms[bestIdx+1]
		next := make([]string, 0, len(syms)-1)
		next = append(next, syms[:bestIdx]...)
		next = append(next, merged)
		next = append(next, syms[bestIdx+2:]...)
		syms = next
		if len(syms) <= 1 {
			break
		}
	}

	t.cache[orig] = syms
	return syms
}

func parseBPETokenizerJSON(data []byte) (*BPETokenizer, error) {
	var raw struct {
		Model struct {
			Type   string            `json:"type"`
			Vocab  map[string]int64  `json:"vocab"`
			Merges any               `json:"merges"`
			UnkID  int64             `json:"unk_id"`
		} `json:"model"`
		AddedTokens []struct {
			ID      int64  `json:"id"`
			Content string `json:"content"`
			Special bool   `json:"special"`
		} `json:"added_tokens"`
		PostProcessor struct {
			SpecialTokens map[string]specialTokenMeta `json:"special_tokens"`
		} `json:"post_processor"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if strings.ToLower(strings.TrimSpace(raw.Model.Type)) != "bpe" {
		return nil, fmt.Errorf("tokenizer model type is not bpe")
	}
	merges := parseBPETokenizerMerges(raw.Model.Merges)
	if len(merges) == 0 {
		return nil, fmt.Errorf("tokenizer bpe merges missing/empty")
	}
	specialIDs := map[string]int64{}
	for tok, meta := range raw.PostProcessor.SpecialTokens {
		if len(meta.IDs) > 0 {
			specialIDs[tok] = meta.IDs[0]
		}
	}
	for _, at := range raw.AddedTokens {
		if strings.TrimSpace(at.Content) == "" {
			continue
		}
		// Treat all added tokens as special for our purposes; it prevents byte-level splitting.
		specialIDs[at.Content] = at.ID
	}
	padID := pickSpecialID(raw.Model.Vocab, raw.PostProcessor.SpecialTokens, "<|pad|>")
	if padID < 0 {
		padID = pickSpecialID(raw.Model.Vocab, raw.PostProcessor.SpecialTokens, "[PAD]")
	}
	return newBPETokenizer(raw.Model.Vocab, merges, raw.Model.UnkID, padID, specialIDs)
}

func parseBPETokenizerMerges(raw any) []string {
	// Tokenizers may encode merges as:
	// - ["t h", "th e", ...]
	// - [["t","h"], ["th","e"], ...]
	if raw == nil {
		return nil
	}
	out := []string{}
	switch v := raw.(type) {
	case []string:
		for _, s := range v {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		for _, item := range v {
			switch m := item.(type) {
			case string:
				s := strings.TrimSpace(m)
				if s != "" {
					out = append(out, s)
				}
			case []any:
				if len(m) < 2 {
					continue
				}
				a, okA := m[0].(string)
				b, okB := m[1].(string)
				if !okA || !okB {
					continue
				}
				a = strings.TrimSpace(a)
				b = strings.TrimSpace(b)
				if a == "" || b == "" {
					continue
				}
				out = append(out, a+" "+b)
			default:
				// ignore unknown forms
			}
		}
		return out
	default:
		return nil
	}
}

func bytesToUnicode() map[byte]rune {
	// Matches the GPT-2 byte-level BPE "bytes_to_unicode" mapping.
	// This is widely used across byte-level tokenizers and is deterministic.
	chars := make([]int, 0, 256)
	for i := int('!'); i <= int('~'); i++ {
		chars = append(chars, i)
	}
	for i := int(0xA1); i <= int(0xAC); i++ {
		chars = append(chars, i)
	}
	for i := int(0xAE); i <= int(0xFF); i++ {
		chars = append(chars, i)
	}
	seen := make(map[int]bool, len(chars))
	for _, c := range chars {
		seen[c] = true
	}
	n := 0
	for b := 0; b < 256; b++ {
		if seen[b] {
			continue
		}
		chars = append(chars, 256+n)
		n++
	}
	out := make(map[byte]rune, 256)
	for b := 0; b < 256; b++ {
		out[byte(b)] = rune(chars[b])
	}
	return out
}
