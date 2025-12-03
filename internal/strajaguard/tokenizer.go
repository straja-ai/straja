package strajaguard

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

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
