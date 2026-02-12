package strajaguard

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/redact"
	"github.com/straja-ai/straja/internal/safety"
	ort "github.com/yalue/onnxruntime_go"
)

type tokenDecoder interface {
	DecodeIDs(ids []int64) string
}

type qwenRefusalPipelineDetector struct {
	id       string
	kind     string
	modelRef string
	version  string

	seqLen            int
	responseMaxTokens int
	tokenizer         Tokenizer
	decoder           tokenDecoder
	promptTemplate    string
	stopTokenIDs      map[int64]bool
	decisionThreshold *float32

	refusal  *specialistModel
	sessions chan *qwenRefusalPipelineSession
}

type qwenRefusalPipelineSession struct {
	session       *ort.AdvancedSession
	inputIDs      *ort.Tensor[int64]
	attentionMask *ort.Tensor[int64]
	lastLogits    *ort.Tensor[float32]
}

func loadQwenRefusalPipelineDetector(bundleDir string, defaultSeqLen, intraThr, interThr, poolSize int, category string, spec DetectorSpec, versions map[string]string) (Detector, error) {
	id := strings.TrimSpace(spec.ID)
	modelRef := strings.TrimSpace(spec.ModelRef)
	modelPath := resolveSpecialistModelPath(bundleDir, modelRef)
	if modelPath == "" {
		return nil, fmt.Errorf("specialist %s model missing", id)
	}

	modelSeqLen := defaultSeqLen
	if spec.MaxTokens > 0 {
		modelSeqLen = spec.MaxTokens
	}
	responseMaxTokens := spec.ResponseMaxTokens
	if responseMaxTokens <= 0 {
		responseMaxTokens = 48
	}
	if responseMaxTokens > modelSeqLen {
		responseMaxTokens = modelSeqLen
	}

	tokenizerDir := filepath.Join(bundleDir, filepath.FromSlash(strings.TrimSpace(spec.TokenizerDir)))
	tok, err := LoadTokenizerFromDir(tokenizerDir)
	if err != nil {
		return nil, fmt.Errorf("specialist %s load tokenizer: %w", id, err)
	}
	decoder, ok := tok.(tokenDecoder)
	if !ok {
		return nil, fmt.Errorf("specialist %s tokenizer does not support decode", id)
	}
	vs, ok := tok.(vocabSizer)
	if !ok || vs.VocabSize() <= 0 {
		return nil, fmt.Errorf("specialist %s tokenizer missing vocab size", id)
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

	refusalModelRef := strings.TrimSpace(spec.RefusalModelRef)
	if refusalModelRef == "" {
		return nil, fmt.Errorf("specialist %s missing refusal_classifier_model_ref", id)
	}
	refusalTokenizer := strings.TrimSpace(spec.RefusalTokenizer)
	if refusalTokenizer == "" {
		return nil, fmt.Errorf("specialist %s missing refusal_classifier_tokenizer_dir", id)
	}
	refusalSpec := DetectorSpec{
		ID:           id + "_refusal_classifier",
		Kind:         "sequence_classification",
		ModelRef:     refusalModelRef,
		TokenizerDir: refusalTokenizer,
		MaxTokens:    spec.RefusalMaxTokens,
		AttackIdx:    spec.RefusalAttackIdx,
	}
	if refusalSpec.MaxTokens <= 0 {
		refusalSpec.MaxTokens = 256
	}
	refusalModel, err := loadSequenceDetectorModel(bundleDir, defaultSeqLen, intraThr, interThr, poolSize, category, refusalSpec, versions)
	if err != nil {
		return nil, fmt.Errorf("specialist %s load refusal classifier: %w", id, err)
	}

	sessions := make(chan *qwenRefusalPipelineSession, poolSize)
	for i := 0; i < poolSize; i++ {
		vocabSize := readModelVocabSize(filepath.Dir(modelPath))
		if vocabSize <= 0 {
			// Fallback to tokenizer-derived size; may be smaller than model vocab for some tokenizers.
			vocabSize = vs.VocabSize()
		}
		ss, err := newQwenRefusalPipelineSession(modelPath, modelSeqLen, vocabSize, intraThr, interThr)
		if err != nil {
			return nil, fmt.Errorf("specialist %s create generator session %d/%d: %w", id, i+1, poolSize, err)
		}
		sessions <- ss
	}

	var decisionThreshold *float32
	if spec.DecisionThreshold != nil {
		v := *spec.DecisionThreshold
		if v < 0 {
			v = 0
		}
		if v > 1 {
			v = 1
		}
		decisionThreshold = &v
	}

	version := ""
	if versions != nil {
		version = versions[modelRef]
	}
	stopTokens := map[int64]bool{
		151643: true, // <|endoftext|>
		151645: true, // <|im_end|>
	}
	redact.Logf("strajaguard specialists: loaded detector=%s kind=qwen_refusal_pipeline model=%s", id, filepath.Base(modelPath))
	return &qwenRefusalPipelineDetector{
		id:                id,
		kind:              "qwen_refusal_pipeline",
		modelRef:          modelRef,
		version:           version,
		seqLen:            modelSeqLen,
		responseMaxTokens: responseMaxTokens,
		tokenizer:         tok,
		decoder:           decoder,
		promptTemplate:    promptTemplate,
		stopTokenIDs:      stopTokens,
		decisionThreshold: decisionThreshold,
		refusal:           refusalModel,
		sessions:          sessions,
	}, nil
}

func (d *qwenRefusalPipelineDetector) Evaluate(ctx context.Context, normalizedText string) (out safety.DetectorResult) {
	start := time.Now()
	out = safety.DetectorResult{
		ID:       d.id,
		Kind:     d.kind,
		ModelRef: d.modelRef,
		Version:  d.version,
	}
	defer func() {
		out.LatencyMs = float64(time.Since(start)) / float64(time.Millisecond)
	}()

	if d == nil || d.sessions == nil || d.tokenizer == nil || d.refusal == nil {
		out.Error = "detector not initialized"
		return out
	}
	if strings.TrimSpace(normalizedText) == "" {
		score := float32(0)
		out.Score = &score
		return out
	}

	prompt := strings.ReplaceAll(d.promptTemplate, "{input}", normalizedText)
	ids, mask := d.tokenizer.Encode(prompt, d.seqLen)
	active := 0
	for _, v := range mask {
		if v != 0 {
			active++
		}
	}
	if active <= 0 || active > len(ids) {
		out.Error = fmt.Sprintf("invalid prompt tokenization active=%d len=%d", active, len(ids))
		return out
	}

	ss := <-d.sessions
	defer func() { d.sessions <- ss }()

	generated := make([]int64, 0, d.responseMaxTokens)
	for step := 0; step < d.responseMaxTokens && active < len(ids); step++ {
		copy(ss.inputIDs.GetData(), ids)
		copy(ss.attentionMask.GetData(), mask)

		if err := ss.session.Run(); err != nil {
			out.Error = redact.String(sanitizeDetectorError(err.Error(), d.modelRef, d.modelRef))
			return out
		}
		logits := ss.lastLogits.GetData()
		if len(logits) == 0 {
			break
		}
		nextID := int64(argmaxFloat32(logits))
		ids[active] = nextID
		mask[active] = 1
		active++
		generated = append(generated, nextID)
		if d.stopTokenIDs[nextID] {
			break
		}
	}

	generatedText := strings.TrimSpace(d.decoder.DecodeIDs(generated))
	if generatedText == "" {
		generatedText = "<empty>"
	}

	score, err := d.refusal.runSequence(generatedText, requestIDFromContext(ctx))
	if err != nil {
		out.Error = redact.String(sanitizeDetectorError(err.Error(), d.modelRef, d.modelRef))
		return out
	}
	if d.decisionThreshold != nil {
		if score >= *d.decisionThreshold {
			score = 1
		} else {
			score = 0
		}
	}
	out.Score = &score
	return out
}

func argmaxFloat32(v []float32) int {
	if len(v) == 0 {
		return 0
	}
	bestIdx := 0
	bestVal := v[0]
	for i := 1; i < len(v); i++ {
		if v[i] > bestVal {
			bestVal = v[i]
			bestIdx = i
		}
	}
	return bestIdx
}

func readModelVocabSize(modelDir string) int {
	cfgPath := filepath.Join(modelDir, "config.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return 0
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return 0
	}
	if val, ok := cfg["vocab_size"]; ok {
		switch num := val.(type) {
		case float64:
			return int(num)
		case int:
			return num
		case int64:
			return int(num)
		}
	}
	return 0
}

func newQwenRefusalPipelineSession(modelPath string, seqLen int, vocabSize int, intraThr, interThr int) (*qwenRefusalPipelineSession, error) {
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

	inputShape := ort.NewShape(1, int64(seqLen))
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

	if vocabSize <= 0 {
		return nil, fmt.Errorf("vocab_size must be > 0")
	}
	lastLogits, err := ort.NewEmptyTensor[float32](ort.NewShape(1, int64(vocabSize)))
	if err != nil {
		opts.Destroy()
		return nil, fmt.Errorf("allocate last_logits tensor: %w", err)
	}

	session, err := ort.NewAdvancedSession(
		modelPath,
		[]string{"input_ids", "attention_mask"},
		[]string{"last_logits"},
		[]ort.Value{inputIDs, attnMask},
		[]ort.Value{lastLogits},
		opts,
	)
	if err != nil {
		opts.Destroy()
		return nil, fmt.Errorf("create onnx session: %w", err)
	}
	opts.Destroy()

	return &qwenRefusalPipelineSession{
		session:       session,
		inputIDs:      inputIDs,
		attentionMask: attnMask,
		lastLogits:    lastLogits,
	}, nil
}
