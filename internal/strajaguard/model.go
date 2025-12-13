package strajaguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	ort "github.com/yalue/onnxruntime_go"
	"gopkg.in/yaml.v3"
)

// LabelThresholds represents warn/block cutoffs for one label.
type LabelThresholds struct {
	Warn  *float32 `yaml:"warn" json:"warn"`
	Block *float32 `yaml:"block" json:"block"`
}

// StrajaGuardResult captures raw scores and derived flags.
type StrajaGuardResult struct {
	Scores map[string]float32 `json:"scores"`
	Flags  []string           `json:"flags"`
}

type sgSession struct {
	session       *ort.AdvancedSession
	inputIDs      *ort.Tensor[int64]
	attentionMask *ort.Tensor[int64]
	output        *ort.Tensor[float32]
}

// StrajaGuardModel wraps the ONNX session pool and tokenizer.
type StrajaGuardModel struct {
	tokenizer  *WordPieceTokenizer
	labels     []string
	thresholds map[string]LabelThresholds
	seqLen     int

	sessions chan *sgSession
	poolSize int
}

// LoadModel initializes the ONNX session, tokenizer, and thresholds.
func LoadModel(bundleDir string, seqLen int) (*StrajaGuardModel, error) {
	if bundleDir == "" {
		return nil, errors.New("bundleDir is empty")
	}
	if seqLen <= 0 {
		seqLen = 256
	}

	libPath := resolveSharedLibraryPath(bundleDir)
	if libPath != "" {
		ort.SetSharedLibraryPath(libPath)
	} else {
		return nil, fmt.Errorf("onnxruntime shared library not found; set ONNXRUNTIME_SHARED_LIBRARY_PATH or install the runtime")
	}
	if !ort.IsInitialized() {
		if err := ort.InitializeEnvironment(); err != nil {
			return nil, fmt.Errorf("initialize onnxruntime: %w", err)
		}
	}

	// Model + external data files; re-exported as strajaguard_v1.*
	modelPath := filepath.Join(bundleDir, "strajaguard_v1.onnx")
	labelsPath := filepath.Join(bundleDir, "label_map.json")
	thresholdsPath := filepath.Join(bundleDir, "thresholds.yaml")
	vocabPath := filepath.Join(bundleDir, "tokenizer", "vocab.txt")

	if _, err := os.Stat(modelPath); err != nil {
		return nil, fmt.Errorf("model file missing at %s: %w", modelPath, err)
	}
	if _, err := os.Stat(modelPath + ".data"); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("model external data unreadable at %s.data: %w", modelPath, err)
	}

	labels, err := loadLabels(labelsPath)
	if err != nil {
		return nil, fmt.Errorf("load labels: %w", err)
	}

	th, err := loadThresholds(thresholdsPath)
	if err != nil {
		return nil, fmt.Errorf("load thresholds: %w", err)
	}

	tokenizer, err := LoadWordPieceTokenizer(vocabPath)
	if err != nil {
		return nil, fmt.Errorf("load tokenizer: %w", err)
	}

	poolSize := maxSessionsFromEnv()
	sessions := make(chan *sgSession, poolSize)
	for i := 0; i < poolSize; i++ {
		ss, err := newSession(modelPath, seqLen, len(labels))
		if err != nil {
			return nil, fmt.Errorf("create onnx session %d/%d: %w", i+1, poolSize, err)
		}
		sessions <- ss
	}

	return &StrajaGuardModel{
		tokenizer:  tokenizer,
		labels:     labels,
		thresholds: th,
		seqLen:     seqLen,
		sessions:   sessions,
		poolSize:   poolSize,
	}, nil
}

// Evaluate runs inference on the combined system + user text.
func (m *StrajaGuardModel) Evaluate(systemPrompt, userText string) (*StrajaGuardResult, error) {
	if m == nil || m.tokenizer == nil || m.sessions == nil {
		return nil, errors.New("straja guard model not initialized")
	}

	waitStart := time.Now()
	ss := <-m.sessions
	waitDur := time.Since(waitStart)
	defer func() { m.sessions <- ss }()

	combined := buildInputText(systemPrompt, userText)
	inputIDs, attn := m.tokenizer.Encode(combined, m.seqLen)

	copy(ss.inputIDs.GetData(), inputIDs)
	copy(ss.attentionMask.GetData(), attn)

	computeStart := time.Now()
	if err := ss.session.Run(); err != nil {
		return nil, fmt.Errorf("onnx run: %w", err)
	}
	computeDur := time.Since(computeStart)
	log.Printf("debug: strajaguard_inference wait_ms=%.2f compute_ms=%.2f pool_size=%d",
		durationMs(waitDur), durationMs(computeDur), m.poolSize)

	raw := ss.output.GetData()
	scores := make(map[string]float32, len(m.labels))
	flags := []string{}

	for i, logit := range raw {
		if i >= len(m.labels) {
			break
		}
		label := m.labels[i]
		score := float32(1.0 / (1.0 + math.Exp(-float64(logit))))
		scores[label] = score

		if th, ok := m.thresholds[label]; ok {
			if th.Block != nil && score >= *th.Block {
				flags = append(flags, label+"_high")
			} else if th.Warn != nil && score >= *th.Warn {
				flags = append(flags, label+"_medium")
			}
		}
	}

	return &StrajaGuardResult{
		Scores: scores,
		Flags:  flags,
	}, nil
}

// Warmup runs a lightweight inference to prime the ONNX runtime and caches.
func (m *StrajaGuardModel) Warmup(sample string) (time.Duration, error) {
	if sample == "" {
		sample = "hello"
	}

	start := time.Now()
	if _, err := m.Evaluate("", sample); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

func buildInputText(systemPrompt, userText string) string {
	if systemPrompt == "" {
		return "[USER]\n" + userText
	}
	return "[SYSTEM]\n" + systemPrompt + "\n[USER]\n" + userText
}

func loadLabels(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		return arr, nil
	}

	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	out := make([]string, len(m))
	for k, v := range m {
		idx, convErr := strconv.Atoi(k)
		if convErr != nil {
			return nil, fmt.Errorf("invalid label index %q: %w", k, convErr)
		}
		if idx < 0 || idx >= len(m) {
			return nil, fmt.Errorf("label index %d out of range", idx)
		}
		out[idx] = v
	}
	return out, nil
}

func loadThresholds(path string) (map[string]LabelThresholds, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var wrapper struct {
		Thresholds map[string]LabelThresholds `yaml:"thresholds"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Thresholds == nil {
		wrapper.Thresholds = make(map[string]LabelThresholds)
	}
	return wrapper.Thresholds, nil
}

// resolveSharedLibraryPath attempts to locate a platform-specific onnxruntime shared library.
// If ONNXRUNTIME_SHARED_LIBRARY_PATH is set, it wins; otherwise we probe common names/locations.
func resolveSharedLibraryPath(bundleDir string) string {
	if env := strings.TrimSpace(os.Getenv("ONNXRUNTIME_SHARED_LIBRARY_PATH")); env != "" {
		return env
	}

	names := []string{
		"libonnxruntime.dylib",
		"onnxruntime.dylib",
		"libonnxruntime.so",
		"onnxruntime.so",
		"onnxruntime.dll",
	}
	dirs := []string{
		bundleDir,
		filepath.Join(bundleDir, "lib"),
		".",
		"/opt/homebrew/lib",
		"/usr/local/lib",
		"/usr/lib",
	}

	for _, dir := range dirs {
		for _, name := range names {
			candidate := filepath.Join(dir, name)
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}
	return ""
}

func newSession(modelPath string, seqLen, numLabels int) (*sgSession, error) {
	inputShape := ort.NewShape(1, int64(seqLen))
	inputIDs, err := ort.NewEmptyTensor[int64](inputShape)
	if err != nil {
		return nil, fmt.Errorf("allocate input_ids tensor: %w", err)
	}
	attnMask, err := ort.NewEmptyTensor[int64](inputShape)
	if err != nil {
		return nil, fmt.Errorf("allocate attention_mask tensor: %w", err)
	}
	outputShape := ort.NewShape(1, int64(numLabels))
	output, err := ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		return nil, fmt.Errorf("allocate output tensor: %w", err)
	}

	session, err := ort.NewAdvancedSession(
		modelPath,
		[]string{"input_ids", "attention_mask"},
		[]string{"logits"},
		[]ort.Value{inputIDs, attnMask},
		[]ort.Value{output},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("create onnx session: %w", err)
	}

	return &sgSession{
		session:       session,
		inputIDs:      inputIDs,
		attentionMask: attnMask,
		output:        output,
	}, nil
}

func maxSessionsFromEnv() int {
	def := runtime.NumCPU()
	if def < 1 {
		def = 1
	}
	if def > 8 {
		def = 8
	}

	if val := strings.TrimSpace(os.Getenv("STRAJA_GUARD_MAX_SESSIONS")); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			if n > 8 {
				n = 8
			}
			return n
		}
	}
	return def
}

func durationMs(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(d.Microseconds()) / 1000
}
