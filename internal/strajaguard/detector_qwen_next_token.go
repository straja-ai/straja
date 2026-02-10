package strajaguard

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/redact"
	"github.com/straja-ai/straja/internal/safety"
	ort "github.com/yalue/onnxruntime_go"
)

// qwen_next_token runs a causal LM ONNX wrapper that returns per-step logits for two
// label token sequences (jailbreak/benign) plus per-step logsumexp for normalization.
//
// Export expectation (intel bundle):
// - inputs: input_ids[int64]{1,seq_len}, attention_mask[int64]{1,seq_len}
// - outputs:
//   - token_logits[float32]{1,K}
//   - logsumexp[float32]{1,K}
type qwenNextTokenDetector struct {
	id     string
	kind   string
	modelRef string
	version string

	seqLen int
	tokenizer Tokenizer
	promptTemplate string
	jailbreakTokenIDs []int
	benignTokenIDs    []int
	maxLen            int

	outputName string
	vocabSize  int
	sessions   chan *qwenNextTokenSession
}

type qwenNextTokenSession struct {
	session       *ort.AdvancedSession
	inputIDs      *ort.Tensor[int64]
	attentionMask *ort.Tensor[int64]
	tokenLogits   *ort.Tensor[float32]
	logSumExp     *ort.Tensor[float32]
}

type vocabSizer interface{ VocabSize() int }

func loadQwenNextTokenDetector(bundleDir string, defaultSeqLen, intraThr, interThr, poolSize int, spec DetectorSpec, versions map[string]string) (Detector, error) {
	id := strings.TrimSpace(spec.ID)
	modelRef := strings.TrimSpace(spec.ModelRef)
	modelPath := resolveSpecialistModelPath(bundleDir, modelRef)
	if modelPath == "" {
		return nil, fmt.Errorf("specialist %s model missing", id)
	}

	modelDir := filepath.Dir(filepath.FromSlash(modelRef))
	if modelDir == "." || modelDir == "" {
		modelDir = id
	}

	modelSeqLen := defaultSeqLen
	if spec.MaxTokens > 0 {
		modelSeqLen = spec.MaxTokens
	}

	tokenizerDir := filepath.Join(bundleDir, filepath.FromSlash(strings.TrimSpace(spec.TokenizerDir)))
	if tokenizerDir == "" || tokenizerDir == bundleDir {
		tokenizerDir = filepath.Join(bundleDir, filepath.FromSlash(modelDir))
	}
	tok, err := LoadTokenizerFromDir(tokenizerDir)
	if err != nil {
		return nil, fmt.Errorf("specialist %s load tokenizer: %w", id, err)
	}

	promptPath := filepath.Join(bundleDir, filepath.FromSlash(strings.TrimSpace(spec.PromptTemplate)))
	if strings.TrimSpace(spec.PromptTemplate) == "" {
		return nil, fmt.Errorf("specialist %s missing prompt_template", id)
	}
	promptBytes, err := os.ReadFile(promptPath)
	if err != nil {
		return nil, fmt.Errorf("specialist %s read prompt_template: %w", id, err)
	}
	promptTemplate := string(promptBytes)
	if !strings.Contains(promptTemplate, "{input}") {
		return nil, fmt.Errorf("specialist %s prompt_template missing {input} placeholder", id)
	}

	labelPath := filepath.Join(bundleDir, filepath.FromSlash(strings.TrimSpace(spec.LabelTokens)))
	if strings.TrimSpace(spec.LabelTokens) == "" {
		return nil, fmt.Errorf("specialist %s missing label_tokens", id)
	}
	labelBytes, err := os.ReadFile(labelPath)
	if err != nil {
		return nil, fmt.Errorf("specialist %s read label_tokens: %w", id, err)
	}
	var labels struct {
		Jailbreak []int `json:"jailbreak"`
		Benign    []int `json:"benign"`
		MaxLen    int   `json:"max_len"`
	}
	if err := json.Unmarshal(labelBytes, &labels); err != nil {
		return nil, fmt.Errorf("specialist %s decode label_tokens: %w", id, err)
	}
	if len(labels.Jailbreak) == 0 || len(labels.Benign) == 0 {
		return nil, fmt.Errorf("specialist %s label_tokens missing sequences", id)
	}
	maxLen := labels.MaxLen
	if maxLen <= 0 {
		if len(labels.Jailbreak) > len(labels.Benign) {
			maxLen = len(labels.Jailbreak)
		} else {
			maxLen = len(labels.Benign)
		}
	}

	// Output names are fixed by our exporter.
	outputName := "token_logits"

	sessions := make(chan *qwenNextTokenSession, poolSize)
	for i := 0; i < poolSize; i++ {
		ss, err := newQwenNextTokenSession(modelPath, modelSeqLen, maxLen, intraThr, interThr)
		if err != nil {
			return nil, fmt.Errorf("specialist %s create onnx session %d/%d: %w", id, i+1, poolSize, err)
		}
		sessions <- ss
	}

	version := ""
	if versions != nil {
		version = versions[modelRef]
	}
	redact.Logf("strajaguard specialists: loaded detector=%s kind=qwen_next_token model=%s", id, filepath.Base(modelPath))
	return &qwenNextTokenDetector{
		id:               id,
		kind:             "qwen_next_token",
		modelRef:         modelRef,
		version:          version,
		seqLen:           modelSeqLen,
		tokenizer:        tok,
		promptTemplate:   promptTemplate,
		jailbreakTokenIDs: labels.Jailbreak,
		benignTokenIDs:    labels.Benign,
		maxLen:            maxLen,
		outputName:        outputName,
		vocabSize:         0,
		sessions:         sessions,
	}, nil
}

func (d *qwenNextTokenDetector) Evaluate(ctx context.Context, normalizedText string) safety.DetectorResult {
	start := time.Now()
	out := safety.DetectorResult{
		ID:       d.id,
		Kind:     d.kind,
		ModelRef: d.modelRef,
		Version:  d.version,
	}
	defer func() {
		out.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
	}()

	if d == nil || d.sessions == nil || d.tokenizer == nil {
		out.Error = "detector not initialized"
		return out
	}
	if strings.TrimSpace(normalizedText) == "" {
		score := float32(0)
		out.Score = &score
		return out
	}

	prompt := strings.ReplaceAll(d.promptTemplate, "{input}", normalizedText)

	ss := <-d.sessions
	defer func() { d.sessions <- ss }()

	// Build batch=2 inputs: jailbreak row + benign row.
	jbIDs, jbMask, err := buildLabelInput(d.tokenizer, prompt, d.jailbreakTokenIDs, d.seqLen)
	if err != nil {
		out.Error = redact.String(err.Error())
		return out
	}
	bnIDs, bnMask, err := buildLabelInput(d.tokenizer, prompt, d.benignTokenIDs, d.seqLen)
	if err != nil {
		out.Error = redact.String(err.Error())
		return out
	}
	inIDs := ss.inputIDs.GetData()
	inMask := ss.attentionMask.GetData()
	if len(inIDs) != 2*d.seqLen || len(inMask) != 2*d.seqLen {
		out.Error = fmt.Sprintf("unexpected input tensor sizes ids=%d mask=%d", len(inIDs), len(inMask))
		return out
	}
	copy(inIDs[:d.seqLen], jbIDs)
	copy(inMask[:d.seqLen], jbMask)
	copy(inIDs[d.seqLen:], bnIDs)
	copy(inMask[d.seqLen:], bnMask)

	if err := ss.session.Run(); err != nil {
		out.Error = redact.String(sanitizeDetectorError(err.Error(), d.modelRef, d.modelRef))
		return out
	}

	tokenLogits := ss.tokenLogits.GetData()
	logsumexp := ss.logSumExp.GetData()
	if len(tokenLogits) == 0 || len(logsumexp) == 0 {
		score := float32(0)
		out.Score = &score
		return out
	}
	k := d.maxLen
	if k <= 0 {
		k = len(tokenLogits) / 2
	}
	if len(tokenLogits) < 2*k || len(logsumexp) < 2*k {
		out.Error = fmt.Sprintf("unexpected output sizes token_logits=%d logsumexp=%d max_len=%d", len(tokenLogits), len(logsumexp), k)
		return out
	}

	lpJB := scoreRow(tokenLogits[:k], logsumexp[:k], k, len(d.jailbreakTokenIDs))
	lpBN := scoreRow(tokenLogits[k:2*k], logsumexp[k:2*k], k, len(d.benignTokenIDs))
	score := probFromLogProbs(lpJB, lpBN)
	out.Score = &score
	return out
}

func buildLabelInput(tok Tokenizer, prompt string, labelIDs []int, seqLen int) ([]int64, []int64, error) {
	ids, mask := tok.Encode(prompt, seqLen)
	if len(ids) != seqLen || len(mask) != seqLen {
		return nil, nil, fmt.Errorf("tokenizer returned unexpected lengths ids=%d mask=%d seq_len=%d", len(ids), len(mask), seqLen)
	}
	n := 0
	for _, v := range mask {
		if v != 0 {
			n++
		}
	}
	padID := int64(0)
	if n >= 0 && n < len(ids) {
		padID = ids[n]
	}

	prefix := make([]int64, 0, n)
	for i := 0; i < n && i < len(ids); i++ {
		prefix = append(prefix, ids[i])
	}
	lbl := make([]int64, 0, len(labelIDs))
	for _, v := range labelIDs {
		lbl = append(lbl, int64(v))
	}
	if len(lbl) >= seqLen {
		lbl = lbl[len(lbl)-seqLen:]
		prefix = nil
	}
	space := seqLen - len(lbl)
	if len(prefix) > space {
		prefix = prefix[len(prefix)-space:]
	}
	combined := append(prefix, lbl...)
	outIDs := make([]int64, seqLen)
	outMask := make([]int64, seqLen)
	pad := seqLen - len(combined)
	for i := 0; i < pad; i++ {
		outIDs[i] = padID
		outMask[i] = 0
	}
	copy(outIDs[pad:], combined)
	for i := pad; i < seqLen; i++ {
		outMask[i] = 1
	}
	return outIDs, outMask, nil
}

func scoreRow(tokenLogits []float32, logsumexp []float32, k int, labelLen int) float64 {
	if labelLen <= 0 {
		return 0
	}
	start := k - labelLen
	if start < 0 {
		start = 0
	}
	lp := float64(0)
	for i := start; i < k && i < len(tokenLogits) && i < len(logsumexp); i++ {
		lp += float64(tokenLogits[i]) - float64(logsumexp[i])
	}
	return lp
}

func probFromLogProbs(lpA, lpB float64) float32 {
	// score = exp(lpA) / (exp(lpA) + exp(lpB)) in a stable way.
	if lpA > lpB {
		return float32(1.0 / (1.0 + math.Exp(lpB-lpA)))
	}
	return float32(math.Exp(lpA-lpB) / (1.0 + math.Exp(lpA-lpB)))
}

func newQwenNextTokenSession(modelPath string, seqLen int, maxLen int, intraThr, interThr int) (*qwenNextTokenSession, error) {
	opts, err := ort.NewSessionOptions()
	if err != nil {
		return nil, fmt.Errorf("create session options: %w", err)
	}
	if err := opts.SetGraphOptimizationLevel(ort.GraphOptimizationLevelEnableAll); err != nil {
		opts.Destroy()
		return nil, fmt.Errorf("set graph optimization: %w", err)
	}
	if err := opts.SetIntraOpNumThreads(intraThr); err != nil {
		opts.Destroy()
		return nil, fmt.Errorf("set intra threads: %w", err)
	}
	if err := opts.SetInterOpNumThreads(interThr); err != nil {
		opts.Destroy()
		return nil, fmt.Errorf("set inter threads: %w", err)
	}

	inputShape := ort.NewShape(2, int64(seqLen))
	inputIDs, err := ort.NewEmptyTensor[int64](inputShape)
	if err != nil {
		opts.Destroy()
		return nil, fmt.Errorf("allocate input_ids tensor: %w", err)
	}
	attnMask, err := ort.NewEmptyTensor[int64](inputShape)
	if err != nil {
		opts.Destroy()
		return nil, fmt.Errorf("allocate attention_mask tensor: %w", err)
	}

	if maxLen <= 0 {
		return nil, fmt.Errorf("maxLen must be > 0")
	}
	tokenLogits, err := ort.NewEmptyTensor[float32](ort.NewShape(2, int64(maxLen)))
	if err != nil {
		opts.Destroy()
		return nil, fmt.Errorf("allocate token_logits tensor: %w", err)
	}
	logSumExp, err := ort.NewEmptyTensor[float32](ort.NewShape(2, int64(maxLen)))
	if err != nil {
		opts.Destroy()
		return nil, fmt.Errorf("allocate logsumexp tensor: %w", err)
	}

	session, err := ort.NewAdvancedSession(
		modelPath,
		[]string{"input_ids", "attention_mask"},
		[]string{"token_logits", "logsumexp"},
		[]ort.Value{inputIDs, attnMask},
		[]ort.Value{tokenLogits, logSumExp},
		opts,
	)
	if err != nil {
		opts.Destroy()
		return nil, fmt.Errorf("create onnx session: %w", err)
	}
	opts.Destroy()

	return &qwenNextTokenSession{
		session:       session,
		inputIDs:      inputIDs,
		attentionMask: attnMask,
		tokenLogits:   tokenLogits,
		logSumExp:     logSumExp,
	}, nil
}
