package strajaguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "embed"

	"github.com/straja-ai/straja/internal/redact"
	"github.com/straja-ai/straja/internal/safety"
	ort "github.com/yalue/onnxruntime_go"
	"gopkg.in/yaml.v3"
)

const (
	SpecialistSourcePromptInjection = "ml:straja/prompt_injection"
	SpecialistSourceJailbreak       = "ml:straja/jailbreak"
	SpecialistSourcePIINER          = "ner:straja/pii_ner"
	SpecialistEntitySource          = "straja:pii_ner"
)

const (
	specialistsConfigSourceEmbedded = "embedded_default"
	specialistsConfigSourceFile     = "file"
)

//go:embed specialists_default.yaml
var embeddedSpecialistsConfig []byte

type SpecialistsEngine interface {
	AnalyzeText(ctx context.Context, text string) (*SpecialistsResult, error)
}

type SpecialistsResult struct {
	Scores      map[string]float32
	PIIEntities []safety.PIIEntity
	Detections  *safety.StrajaGuardDetections
}

type requestIDKey struct{}

// WithRequestID stores the request id in context for debug logging.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	if ctx == nil || strings.TrimSpace(requestID) == "" {
		return ctx
	}
	return context.WithValue(ctx, requestIDKey{}, requestID)
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}

type SpecialistsConfig struct {
	// Detectors is the preferred (multi-detector) config for prompt injection and jailbreak.
	Detectors SpecialistsDetectorsConfig `yaml:"detectors"`
	// Ensemble controls aggregation for prompt injection and jailbreak.
	Ensemble SpecialistsEnsembleConfig `yaml:"ensemble"`

	// Specialists is legacy single-specialist config (still used for pii_ner, and as a fallback
	// for prompt_injection/jailbreak when Detectors is omitted).
	Specialists map[string]SpecialistConfig `yaml:"specialists"`
}

type SpecialistConfig struct {
	Kind         string `yaml:"kind"`
	Onnx         string `yaml:"onnx"`
	TokenizerDir string `yaml:"tokenizer_dir"`
	MaxTokens    int    `yaml:"max_tokens"`
}

type Specialists struct {
	seqLen     int
	categories map[string]*categoryEngine
	piiNER     *specialistModel
}

type SpecialistsDetectorsConfig struct {
	PromptInjection []DetectorSpec `yaml:"prompt_injection"`
	Jailbreak       []DetectorSpec `yaml:"jailbreak"`
}

type SpecialistsEnsembleConfig struct {
	PromptInjection EnsembleSpec `yaml:"prompt_injection"`
	Jailbreak       EnsembleSpec `yaml:"jailbreak"`
}

type DetectorSpec struct {
	ID           string `yaml:"id"`
	Kind         string `yaml:"kind"`
	ModelRef     string `yaml:"model_ref"`
	TokenizerDir string `yaml:"tokenizer_dir"`
	MaxTokens    int    `yaml:"max_tokens"`
	Enabled      *bool  `yaml:"enabled"`
	AttackIdx    *int   `yaml:"attack_idx"`

	// qwen_next_token specific assets (bundle-relative paths).
	PromptTemplate string `yaml:"prompt_template"`
	LabelTokens    string `yaml:"label_tokens"`
}

func detectorEnabled(spec DetectorSpec) bool {
	if spec.Enabled == nil {
		return true
	}
	return *spec.Enabled
}

type EnsembleSpec struct {
	Method    string  `yaml:"method"`    // any | mean
	Threshold float32 `yaml:"threshold"` // used only for "attack" boolean in transparency payloads
}

type Detector interface {
	Evaluate(ctx context.Context, normalizedText string) safety.DetectorResult
}

type categoryEngine struct {
	category  string
	method    string
	threshold float32
	detectors []Detector
}

var warnLegacySpecialistsOnce sync.Once

type specialistModel struct {
	id             string
	kind           string
	modelRef       string
	version        string
	modelPath      string
	tokenizer      Tokenizer
	labels         []string
	seqLen         int
	sessions       chan *specialistSession
	poolSize       int
	numLabels      int
	needsTokenType bool
	outputName     string
	outputDims     []int64
	attackIdx      int
	attackLabel    string
}

type specialistSession struct {
	session       *ort.AdvancedSession
	inputIDs      *ort.Tensor[int64]
	attentionMask *ort.Tensor[int64]
	tokenTypeIDs  *ort.Tensor[int64]
	output        *ort.Tensor[float32]
}

type sequenceDetector struct {
	m *specialistModel
}

func (d *sequenceDetector) Evaluate(ctx context.Context, normalizedText string) safety.DetectorResult {
	if d == nil || d.m == nil {
		return safety.DetectorResult{
			ID:    "",
			Kind:  "sequence_classification",
			Error: "detector not initialized",
		}
	}
	start := time.Now()
	score, err := d.m.runSequence(normalizedText, requestIDFromContext(ctx))
	lat := time.Since(start)

	out := safety.DetectorResult{
		ID:        d.m.id,
		Kind:      d.m.kind,
		ModelRef:  d.m.modelRef,
		LatencyMs: float64(lat.Microseconds()) / 1000.0,
		Version:   d.m.version,
	}
	if err != nil {
		out.Error = redact.String(sanitizeDetectorError(err.Error(), d.m.modelPath, d.m.modelRef))
		return out
	}
	out.Score = ptrF32(score)
	return out
}

func ptrF32(v float32) *float32 { return &v }

func sanitizeDetectorError(msg string, modelPath string, modelRef string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return msg
	}
	// Avoid leaking absolute paths in activation payloads.
	if strings.TrimSpace(modelPath) != "" {
		msg = strings.ReplaceAll(msg, modelPath, strings.TrimSpace(modelRef))
	}
	return msg
}

// LoadSpecialistsEngine builds a multi-model specialists engine from a bundle dir.
func LoadSpecialistsEngine(bundleDir string, seqLen int, rt RuntimeSettings, configPath string) (*Specialists, string, error) {
	if bundleDir == "" {
		return nil, "", errors.New("bundleDir is empty")
	}
	if seqLen <= 0 {
		seqLen = 256
	}

	cfg, source, err := loadSpecialistsConfigWithFallback(configPath)
	if err != nil {
		return nil, "", fmt.Errorf("load specialists config: %w", err)
	}
	if len(cfg.Specialists) == 0 && len(cfg.Detectors.PromptInjection) == 0 && len(cfg.Detectors.Jailbreak) == 0 {
		return nil, "", errors.New("specialists config is empty")
	}
	redact.Logf("strajaguard specialists: config_source=%s", source)

	libPath := resolveSharedLibraryPath(bundleDir)
	if libPath != "" {
		ort.SetSharedLibraryPath(libPath)
	} else {
		return nil, "", fmt.Errorf("onnxruntime shared library not found; set ONNXRUNTIME_SHARED_LIBRARY_PATH or install the runtime")
	}
	if !ort.IsInitialized() {
		if err := ort.InitializeEnvironment(); err != nil {
			return nil, "", fmt.Errorf("initialize onnxruntime: %w", err)
		}
	}

	poolSize := 1
	intraThr := rt.IntraThreads
	if intraThr <= 0 {
		intraThr = defaultIntraThreads
	}
	interThr := rt.InterThreads
	if interThr <= 0 {
		interThr = defaultInterThreads
	}

	versions := loadModelVersionsFromManifest(bundleDir)

	promptSpecs, jailbreakSpecs, piiSpec, legacyPresent, legacyUsed := normalizeDetectorConfig(cfg)
	if legacyPresent && !legacyUsed && (len(cfg.Detectors.PromptInjection) > 0 || len(cfg.Detectors.Jailbreak) > 0) {
		warnLegacySpecialistsOnce.Do(func() {
			redact.Logf("strajaguard specialists: both legacy 'specialists' and new 'detectors' config present; using 'detectors'")
		})
	}

	categories := map[string]*categoryEngine{}
	buildCategory := func(category string, method string, threshold float32, specs []DetectorSpec) (*categoryEngine, error) {
		eng := &categoryEngine{
			category:  category,
			method:    normalizeEnsembleMethod(method),
			threshold: normalizeEnsembleThreshold(threshold),
			detectors: nil,
		}
		seen := map[string]bool{}
		for _, spec := range specs {
			if !detectorEnabled(spec) {
				redact.Logf("strajaguard specialists: category=%s detector=%s enabled=false (skipping load)", category, strings.TrimSpace(spec.ID))
				continue
			}
			if strings.TrimSpace(spec.ID) == "" {
				return nil, fmt.Errorf("%s detector missing id", category)
			}
			if seen[spec.ID] {
				return nil, fmt.Errorf("%s detector id %q not unique", category, spec.ID)
			}
			seen[spec.ID] = true
			kind := strings.TrimSpace(strings.ToLower(spec.Kind))
			if kind == "" {
				return nil, fmt.Errorf("%s detector %s missing kind", category, spec.ID)
			}
			modelRef := strings.TrimSpace(spec.ModelRef)
			if modelRef == "" {
				return nil, fmt.Errorf("%s detector %s missing model_ref", category, spec.ID)
			}

			switch kind {
			case "sequence_classification":
				m, err := loadSequenceDetectorModel(bundleDir, seqLen, intraThr, interThr, poolSize, category, spec, versions)
				if err != nil {
					return nil, err
				}
				eng.detectors = append(eng.detectors, &sequenceDetector{m: m})
			case "qwen_next_token":
				d, err := loadQwenNextTokenDetector(bundleDir, seqLen, intraThr, interThr, poolSize, spec, versions)
				if err != nil {
					return nil, err
				}
				eng.detectors = append(eng.detectors, d)
			default:
				return nil, fmt.Errorf("%s detector %s unsupported kind %q", category, spec.ID, spec.Kind)
			}
		}
		return eng, nil
	}

	piEng, err := buildCategory("prompt_injection", cfg.Ensemble.PromptInjection.Method, cfg.Ensemble.PromptInjection.Threshold, promptSpecs)
	if err != nil {
		return nil, "", err
	}
	jbEng, err := buildCategory("jailbreak", cfg.Ensemble.Jailbreak.Method, cfg.Ensemble.Jailbreak.Threshold, jailbreakSpecs)
	if err != nil {
		return nil, "", err
	}
	redact.Logf("strajaguard specialists: category=prompt_injection detectors=%d method=%s threshold=%.3f", len(piEng.detectors), piEng.method, piEng.threshold)
	redact.Logf("strajaguard specialists: category=jailbreak detectors=%d method=%s threshold=%.3f", len(jbEng.detectors), jbEng.method, jbEng.threshold)
	categories["prompt_injection"] = piEng
	categories["jailbreak"] = jbEng

	var piiNER *specialistModel
	if piiSpec != nil && strings.TrimSpace(piiSpec.Kind) != "" {
		m, err := loadNERModel(bundleDir, seqLen, intraThr, interThr, poolSize, "pii_ner", *piiSpec, versions)
		if err != nil {
			return nil, "", err
		}
		piiNER = m
	}

	_ = legacyUsed
	return &Specialists{
		seqLen:     seqLen,
		categories: categories,
		piiNER:     piiNER,
	}, source, nil
}

// LoadSpecialistsConfig reads the specialists config YAML.
func LoadSpecialistsConfig(path string) (*SpecialistsConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("config path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseSpecialistsConfig(data)
}

func loadSpecialistsConfigWithFallback(path string) (*SpecialistsConfig, string, error) {
	if strings.TrimSpace(path) != "" {
		info, err := os.Stat(path)
		if err == nil && info != nil && !info.IsDir() {
			cfg, err := LoadSpecialistsConfig(path)
			if err != nil {
				return nil, "", err
			}
			return cfg, specialistsConfigSourceFile + ":" + path, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, "", err
		}
	}
	if len(embeddedSpecialistsConfig) == 0 {
		return nil, "", errors.New("embedded specialists config is empty")
	}
	cfg, err := parseSpecialistsConfig(embeddedSpecialistsConfig)
	if err != nil {
		return nil, "", err
	}
	return cfg, specialistsConfigSourceEmbedded, nil
}

func parseSpecialistsConfig(data []byte) (*SpecialistsConfig, error) {
	var cfg SpecialistsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func normalizeDetectorConfig(cfg *SpecialistsConfig) (prompt []DetectorSpec, jailbreak []DetectorSpec, pii *SpecialistConfig, legacyPresent bool, legacyUsed bool) {
	if cfg == nil {
		return nil, nil, nil, false, false
	}

	legacyPresent = len(cfg.Specialists) > 0 && (cfg.Specialists["prompt_injection"].Kind != "" || cfg.Specialists["jailbreak"].Kind != "")

	// Preferred path: new multi-detector config.
	if len(cfg.Detectors.PromptInjection) > 0 || len(cfg.Detectors.Jailbreak) > 0 {
		return cfg.Detectors.PromptInjection, cfg.Detectors.Jailbreak, cfg.Specialists["pii_ner"].ptr(), legacyPresent, false
	}

	// Legacy fallback: a single specialist per category under "specialists".
	legacyUsed = true
	if spec, ok := cfg.Specialists["prompt_injection"]; ok && strings.TrimSpace(spec.Kind) != "" {
		prompt = []DetectorSpec{legacyToDetector("prompt_injection", spec)}
	}
	if spec, ok := cfg.Specialists["jailbreak"]; ok && strings.TrimSpace(spec.Kind) != "" {
		jailbreak = []DetectorSpec{legacyToDetector("jailbreak", spec)}
	}
	if spec, ok := cfg.Specialists["pii_ner"]; ok && strings.TrimSpace(spec.Kind) != "" {
		cpy := spec
		pii = &cpy
	}
	return prompt, jailbreak, pii, legacyPresent, legacyUsed
}

func legacyToDetector(category string, spec SpecialistConfig) DetectorSpec {
	return DetectorSpec{
		ID:           category,
		Kind:         spec.Kind,
		ModelRef:     spec.Onnx,
		TokenizerDir: spec.TokenizerDir,
		MaxTokens:    spec.MaxTokens,
		Enabled:      nil,
	}
}

func (c SpecialistConfig) ptr() *SpecialistConfig {
	if strings.TrimSpace(c.Kind) == "" && strings.TrimSpace(c.Onnx) == "" && strings.TrimSpace(c.TokenizerDir) == "" {
		return nil
	}
	cc := c
	return &cc
}

func loadModelVersionsFromManifest(bundleDir string) map[string]string {
	// Best-effort: manifest metadata is optional and older bundles don't have it.
	path := filepath.Join(bundleDir, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}
	var raw struct {
		Metadata struct {
			Models []struct {
				ModelRef string `json:"model_ref"`
				Version  string `json:"version"`
			} `json:"models"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	out := map[string]string{}
	for _, m := range raw.Metadata.Models {
		ref := strings.TrimSpace(m.ModelRef)
		ver := strings.TrimSpace(m.Version)
		if ref == "" || ver == "" {
			continue
		}
		out[ref] = ver
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func loadSequenceDetectorModel(bundleDir string, defaultSeqLen, intraThr, interThr, poolSize int, category string, spec DetectorSpec, versions map[string]string) (*specialistModel, error) {
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

	tokenizerDir := filepath.Join(bundleDir, filepath.FromSlash(strings.TrimSpace(spec.TokenizerDir)))
	if tokenizerDir == "" || tokenizerDir == bundleDir {
		tokenizerDir = filepath.Join(bundleDir, filepath.FromSlash(modelDir))
	}
	tokenizer, err := LoadTokenizerFromDir(tokenizerDir)
	if err != nil {
		return nil, fmt.Errorf("specialist %s load tokenizer: %w", id, err)
	}

	configDir := filepath.Join(bundleDir, filepath.FromSlash(modelDir))
	meta, err := loadSpecialistMeta(configDir)
	if err != nil {
		return nil, fmt.Errorf("specialist %s load config: %w", id, err)
	}
	labels, numLabels := meta.Labels, meta.NumLabels
	if numLabels <= 0 {
		numLabels = len(labels)
	}
	if numLabels <= 0 {
		numLabels = 1
	}

	modelSeqLen := defaultSeqLen
	if spec.MaxTokens > 0 {
		modelSeqLen = spec.MaxTokens
	}

	needsTokenType := meta.RequiresTokenType
	outputName, outputDims, err := selectOutputInfo(modelPath)
	if err != nil {
		return nil, fmt.Errorf("specialist %s output selection: %w", id, err)
	}
	if debugML() {
		redact.Logf("strajaguard debug ml: model=%s output_name=%s output_dims=%v", id, outputName, outputDims)
	}
	attackIdx, attackLabel := pickAttackClass(strings.TrimSpace(strings.ToLower(category)), meta, numLabels)
	if spec.AttackIdx != nil {
		idx := *spec.AttackIdx
		if idx >= 0 && idx < numLabels {
			attackIdx = idx
			if lbl, ok := meta.ID2Label[idx]; ok {
				attackLabel = lbl
			} else {
				attackLabel = fmt.Sprintf("%d", idx)
			}
		}
	}
	if debugML() {
		redact.Logf("strajaguard debug ml: model=%s attack_class_index=%d attack_label=%s", id, attackIdx, attackLabel)
	}
	sessions := make(chan *specialistSession, poolSize)
	for i := 0; i < poolSize; i++ {
		ss, err := newSpecialistSession(modelPath, modelSeqLen, numLabels, outputDims, intraThr, interThr, false, needsTokenType, outputName)
		if err != nil {
			return nil, fmt.Errorf("specialist %s create onnx session %d/%d: %w", id, i+1, poolSize, err)
		}
		sessions <- ss
	}
	version := ""
	if versions != nil {
		version = versions[modelRef]
	}
	m := &specialistModel{
		id:             id,
		kind:           "sequence_classification",
		modelRef:       modelRef,
		version:        version,
		modelPath:      modelPath,
		tokenizer:      tokenizer,
		labels:         labels,
		seqLen:         modelSeqLen,
		sessions:       sessions,
		poolSize:       poolSize,
		numLabels:      numLabels,
		needsTokenType: needsTokenType,
		outputName:     outputName,
		outputDims:     outputDims,
		attackIdx:      attackIdx,
		attackLabel:    attackLabel,
	}
	redact.Logf("strajaguard specialists: loaded detector=%s kind=%s model=%s", id, m.kind, filepath.Base(modelPath))
	return m, nil
}

func loadNERModel(bundleDir string, defaultSeqLen, intraThr, interThr, poolSize int, id string, spec SpecialistConfig, versions map[string]string) (*specialistModel, error) {
	id = strings.TrimSpace(id)
	modelRef := strings.TrimSpace(spec.Onnx)
	modelPath := resolveSpecialistModelPath(bundleDir, modelRef)
	if modelPath == "" {
		return nil, fmt.Errorf("specialist %s model missing", id)
	}
	modelDir := filepath.Dir(filepath.FromSlash(modelRef))
	if modelDir == "." || modelDir == "" {
		modelDir = id
	}

	tokenizerDir := filepath.Join(bundleDir, filepath.FromSlash(strings.TrimSpace(spec.TokenizerDir)))
	if tokenizerDir == "" || tokenizerDir == bundleDir {
		tokenizerDir = filepath.Join(bundleDir, filepath.FromSlash(modelDir))
	}
	tokenizer, err := LoadTokenizerFromDir(tokenizerDir)
	if err != nil {
		return nil, fmt.Errorf("specialist %s load tokenizer: %w", id, err)
	}

	configDir := filepath.Join(bundleDir, filepath.FromSlash(modelDir))
	meta, err := loadSpecialistMeta(configDir)
	if err != nil {
		return nil, fmt.Errorf("specialist %s load config: %w", id, err)
	}
	labels, numLabels := meta.Labels, meta.NumLabels
	if len(labels) == 0 {
		return nil, fmt.Errorf("specialist %s missing token labels", id)
	}
	if numLabels <= 0 {
		numLabels = len(labels)
	}
	if numLabels <= 0 {
		numLabels = 1
	}
	modelSeqLen := defaultSeqLen
	if spec.MaxTokens > 0 {
		modelSeqLen = spec.MaxTokens
	}

	needsTokenType := meta.RequiresTokenType
	outputName, outputDims, err := selectOutputInfo(modelPath)
	if err != nil {
		return nil, fmt.Errorf("specialist %s output selection: %w", id, err)
	}

	sessions := make(chan *specialistSession, poolSize)
	for i := 0; i < poolSize; i++ {
		ss, err := newSpecialistSession(modelPath, modelSeqLen, numLabels, outputDims, intraThr, interThr, true, needsTokenType, outputName)
		if err != nil {
			return nil, fmt.Errorf("specialist %s create onnx session %d/%d: %w", id, i+1, poolSize, err)
		}
		sessions <- ss
	}
	version := ""
	if versions != nil {
		version = versions[modelRef]
	}
	m := &specialistModel{
		id:             id,
		kind:           "token_classification",
		modelRef:       modelRef,
		version:        version,
		modelPath:      modelPath,
		tokenizer:      tokenizer,
		labels:         labels,
		seqLen:         modelSeqLen,
		sessions:       sessions,
		poolSize:       poolSize,
		numLabels:      numLabels,
		needsTokenType: needsTokenType,
		outputName:     outputName,
		outputDims:     outputDims,
		attackIdx:      0,
		attackLabel:    "",
	}
	redact.Logf("strajaguard specialists: loaded %s kind=%s model=%s", id, m.kind, filepath.Base(modelPath))
	return m, nil
}

// AnalyzeText runs all configured specialists on the text.
func (s *Specialists) AnalyzeText(ctx context.Context, text string) (*SpecialistsResult, error) {
	if s == nil {
		return nil, errors.New("specialists engine not initialized")
	}
	res := &SpecialistsResult{
		Scores:     map[string]float32{},
		Detections: &safety.StrajaGuardDetections{},
	}
	reqID := requestIDFromContext(ctx)

	// Run categories + PII in parallel to reduce end-to-end request latency.
	// Each category engine already runs its detectors concurrently.
	var wg sync.WaitGroup
	var pi *safety.CategoryDetections
	var jb *safety.CategoryDetections
	var entities []safety.PIIEntity

	if eng, ok := s.categories["prompt_injection"]; ok && eng != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pi = eng.evaluate(ctx, text)
		}()
	}
	if eng, ok := s.categories["jailbreak"]; ok && eng != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jb = eng.evaluate(ctx, text)
		}()
	}
	if s.piiNER != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ents, err := s.piiNER.runNER(text, reqID)
			if err != nil {
				// PII behavior stays as-is; treat errors as non-fatal (fail-open) and let regex handle the rest.
				redact.Logf("strajaguard pii_ner error: %v", err)
				return
			}
			entities = ents
		}()
	}

	wg.Wait()

	if pi != nil {
		res.Detections.PromptInjection = pi
		res.Scores["prompt_injection"] = pi.Ensemble.Score
		if debugML() {
			redact.Logf("strajaguard debug ml: category=prompt_injection request=%s score=%.4f status=%s", reqID, pi.Ensemble.Score, pi.Ensemble.Status)
		}
	}
	if jb != nil {
		res.Detections.Jailbreak = jb
		res.Scores["jailbreak"] = jb.Ensemble.Score
		if debugML() {
			redact.Logf("strajaguard debug ml: category=jailbreak request=%s score=%.4f status=%s", reqID, jb.Ensemble.Score, jb.Ensemble.Status)
		}
	}
	if s.piiNER != nil {
		res.PIIEntities = entities
		if len(entities) > 0 {
			res.Scores["contains_personal_data"] = 1.0
		} else {
			res.Scores["contains_personal_data"] = 0.0
		}
	}

	// If neither category is configured, omit the field to keep payloads lean.
	return res, nil
}

// Warmup runs a light inference for all specialists.
func (s *Specialists) Warmup(sample string) (time.Duration, error) {
	if s == nil {
		return 0, errors.New("specialists engine not initialized")
	}
	start := time.Now()
	if _, err := s.AnalyzeText(context.Background(), sample); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

func normalizeEnsembleMethod(method string) string {
	m := strings.ToLower(strings.TrimSpace(method))
	switch m {
	case "", "any":
		return "any"
	case "mean", "avg", "average":
		return "mean"
	case "median":
		return "median"
	default:
		// Keep runtime tolerant; treat unknown values as default.
		return "any"
	}
}

func normalizeEnsembleThreshold(v float32) float32 {
	// Default aligns with the gateway's historical block thresholds.
	if v <= 0 {
		return 0.80
	}
	if v > 1 {
		return 1
	}
	return v
}

func (e *categoryEngine) evaluate(ctx context.Context, text string) *safety.CategoryDetections {
	if e == nil {
		return &safety.CategoryDetections{
			Ensemble: safety.EnsembleResult{
				Method:         "any",
				Threshold:      0,
				Score:          0,
				Attack:         false,
				ValidDetectors: 0,
				TotalDetectors: 0,
				Status:         "disabled",
			},
		}
	}

	enabled := e.detectors
	if len(enabled) == 0 {
		return &safety.CategoryDetections{
			Ensemble: safety.EnsembleResult{
				Method:         e.method,
				Threshold:      e.threshold,
				Score:          0,
				Attack:         false,
				ValidDetectors: 0,
				TotalDetectors: 0,
				Status:         "disabled",
			},
		}
	}

	type item struct {
		r safety.DetectorResult
	}
	out := make([]item, len(enabled))
	var wg sync.WaitGroup
	wg.Add(len(enabled))

	for i := range enabled {
		i := i
		go func() {
			defer wg.Done()
			out[i].r = enabled[i].Evaluate(ctx, text)
		}()
	}
	wg.Wait()

	// Stable ordering (by detector id) for UI/tests.
	results := make([]safety.DetectorResult, 0, len(out))
	for _, it := range out {
		results = append(results, it.r)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})

	valid := make([]float32, 0, len(results))
	for _, r := range results {
		if r.Error != "" || r.Score == nil {
			continue
		}
		valid = append(valid, *r.Score)
	}

	ens := safety.EnsembleResult{
		Method:         e.method,
		Threshold:      e.threshold,
		Score:          0,
		Attack:         false,
		ValidDetectors: len(valid),
		TotalDetectors: len(results),
		Status:         "ok",
	}
	if len(valid) == 0 {
		ens.Status = "all_detectors_failed"
		return &safety.CategoryDetections{
			Ensemble:  ens,
			Detectors: results,
		}
	}

	switch e.method {
	case "mean":
		var sum float32
		for _, v := range valid {
			sum += v
		}
		ens.Score = sum / float32(len(valid))
	case "median":
		vals := append([]float32(nil), valid...)
		sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
		n := len(vals)
		if n%2 == 1 {
			ens.Score = vals[n/2]
		} else {
			ens.Score = (vals[n/2-1] + vals[n/2]) / 2
		}
	default: // any
		max := valid[0]
		for _, v := range valid[1:] {
			if v > max {
				max = v
			}
		}
		ens.Score = max
	}
	ens.Attack = ens.Score >= e.threshold
	return &safety.CategoryDetections{
		Ensemble:  ens,
		Detectors: results,
	}
}

func (m *specialistModel) runSequence(text string, requestID string) (float32, error) {
	if m == nil || m.tokenizer == nil || m.sessions == nil {
		return 0, errors.New("specialist model not initialized")
	}
	if strings.TrimSpace(text) == "" {
		return 0, nil
	}

	ss := <-m.sessions
	defer func() { m.sessions <- ss }()

	inputIDs, attn := m.tokenizer.Encode(text, m.seqLen)
	if debugML() {
		logTokenization(m.id, requestID, m.seqLen, inputIDs, attn)
	}
	copy(ss.inputIDs.GetData(), inputIDs)
	copy(ss.attentionMask.GetData(), attn)
	if ss.tokenTypeIDs != nil {
		tokenTypes := ss.tokenTypeIDs.GetData()
		for i := range tokenTypes {
			tokenTypes[i] = 0
		}
	}
	if ss.tokenTypeIDs != nil {
		tokenTypes := ss.tokenTypeIDs.GetData()
		for i := range tokenTypes {
			tokenTypes[i] = 0
		}
	}

	if err := ss.session.Run(); err != nil {
		return 0, fmt.Errorf("onnx run: %w", err)
	}

	raw := ss.output.GetData()
	if len(raw) == 0 {
		return 0, nil
	}
	score, probs, attackIdx, attackLabel := sequenceScore(raw, m.numLabels, m.outputDims, m.attackIdx, m.attackLabel, m.id)
	if debugML() {
		logSequenceDebug(m.id, requestID, raw, probs, attackIdx, attackLabel, score)
	}
	return score, nil
}

func (m *specialistModel) runNER(text string, requestID string) ([]safety.PIIEntity, error) {
	if m == nil || m.tokenizer == nil || m.sessions == nil {
		return nil, errors.New("specialist model not initialized")
	}
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}

	ss := <-m.sessions
	defer func() { m.sessions <- ss }()

	offsetTok, ok := m.tokenizer.(OffsetTokenizer)
	if !ok {
		return nil, errors.New("tokenizer does not support offsets")
	}
	inputIDs, attn, offsets := offsetTok.EncodeWithOffsets(text, m.seqLen)
	if debugML() {
		logTokenization(m.id, requestID, m.seqLen, inputIDs, attn)
	}
	copy(ss.inputIDs.GetData(), inputIDs)
	copy(ss.attentionMask.GetData(), attn)
	if ss.tokenTypeIDs != nil {
		tokenTypes := ss.tokenTypeIDs.GetData()
		for i := range tokenTypes {
			tokenTypes[i] = 0
		}
	}
	if ss.tokenTypeIDs != nil {
		tokenTypes := ss.tokenTypeIDs.GetData()
		for i := range tokenTypes {
			tokenTypes[i] = 0
		}
	}

	if err := ss.session.Run(); err != nil {
		return nil, fmt.Errorf("onnx run: %w", err)
	}

	logits := ss.output.GetData()
	if len(logits) == 0 || len(m.labels) == 0 {
		return nil, nil
	}

	labels := make([]string, len(offsets))
	for i := 0; i < len(offsets); i++ {
		if i*m.numLabels >= len(logits) {
			break
		}
		best := 0
		bestScore := float32(-math.MaxFloat32)
		base := i * m.numLabels
		for j := 0; j < m.numLabels && base+j < len(logits); j++ {
			if logits[base+j] > bestScore {
				best = j
				bestScore = logits[base+j]
			}
		}
		if best < len(m.labels) {
			labels[i] = m.labels[best]
		}
	}

	return entitiesFromTokenLabels(labels, offsets), nil
}

func entitiesFromTokenLabels(labels []string, offsets []tokenOffset) []safety.PIIEntity {
	if len(labels) == 0 || len(offsets) == 0 {
		return nil
	}
	var entities []safety.PIIEntity
	var cur *safety.PIIEntity

	for i, lbl := range labels {
		if i >= len(offsets) {
			break
		}
		offset := offsets[i]
		if offset.Start < 0 || offset.End <= offset.Start {
			continue
		}
		prefix, typ := splitLabel(lbl)
		if typ == "" || strings.EqualFold(lbl, "O") {
			if cur != nil {
				entities = append(entities, *cur)
				cur = nil
			}
			continue
		}
		if prefix == "B" || cur == nil || !strings.EqualFold(cur.EntityType, typ) {
			if cur != nil {
				entities = append(entities, *cur)
			}
			cur = &safety.PIIEntity{
				EntityType: typ,
				StartByte:  offset.Start,
				EndByte:    offset.End,
				Source:     SpecialistEntitySource,
			}
			continue
		}
		if prefix == "I" && cur != nil {
			if offset.End > cur.EndByte {
				cur.EndByte = offset.End
			}
		}
	}
	if cur != nil {
		entities = append(entities, *cur)
	}
	return mergeEntities(entities)
}

func splitLabel(lbl string) (string, string) {
	lbl = strings.TrimSpace(lbl)
	if lbl == "" {
		return "", ""
	}
	parts := strings.SplitN(lbl, "-", 2)
	if len(parts) == 1 {
		return "", lbl
	}
	return parts[0], parts[1]
}

func mergeEntities(in []safety.PIIEntity) []safety.PIIEntity {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].StartByte == in[j].StartByte {
			return in[i].EndByte < in[j].EndByte
		}
		return in[i].StartByte < in[j].StartByte
	})
	out := make([]safety.PIIEntity, 0, len(in))
	cur := in[0]
	for _, ent := range in[1:] {
		if ent.StartByte <= cur.EndByte && strings.EqualFold(ent.EntityType, cur.EntityType) {
			if ent.EndByte > cur.EndByte {
				cur.EndByte = ent.EndByte
			}
			continue
		}
		out = append(out, cur)
		cur = ent
	}
	out = append(out, cur)
	return out
}

func resolveSpecialistModelPath(bundleDir, rel string) string {
	if bundleDir == "" {
		return ""
	}
	rel = filepath.FromSlash(strings.TrimSpace(rel))
	modelDir := filepath.Dir(rel)
	if modelDir == "." || modelDir == "" {
		modelDir = ""
	}
	int8Path := filepath.Join(bundleDir, modelDir, "model.int8.onnx")
	if _, err := os.Stat(int8Path); err == nil {
		return int8Path
	}
	modelPath := filepath.Join(bundleDir, rel)
	if _, err := os.Stat(modelPath); err == nil {
		return modelPath
	}
	fallback := filepath.Join(bundleDir, modelDir, "model.onnx")
	if _, err := os.Stat(fallback); err == nil {
		return fallback
	}
	return ""
}

type specialistMeta struct {
	Labels            []string
	NumLabels         int
	ID2Label          map[int]string
	Label2ID          map[string]int
	RequiresTokenType bool
}

func loadSpecialistMeta(dir string) (specialistMeta, error) {
	meta := specialistMeta{}
	configPath := filepath.Join(dir, "config.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var cfg struct {
			NumLabels     int            `json:"num_labels"`
			ID2Label      map[string]any `json:"id2label"`
			Label2ID      map[string]int `json:"label2id"`
			TypeVocabSize int            `json:"type_vocab_size"`
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return meta, err
		}
		meta.NumLabels = cfg.NumLabels
		meta.ID2Label = labelsMapFromIDAny(cfg.ID2Label)
		meta.Label2ID = cfg.Label2ID
		meta.Labels = labelsFromIDMapAny(cfg.ID2Label)
		meta.RequiresTokenType = cfg.TypeVocabSize > 0
	}

	labelPath := filepath.Join(dir, "label_map.json")
	if data, err := os.ReadFile(labelPath); err == nil {
		var list []string
		if err := json.Unmarshal(data, &list); err == nil && len(list) > 0 {
			meta.Labels = list
			meta.NumLabels = len(list)
		} else {
			var idMap map[string]string
			if err := json.Unmarshal(data, &idMap); err == nil {
				meta.Labels = labelsFromIDMap(idMap)
				meta.NumLabels = len(meta.Labels)
				meta.ID2Label = labelsMapFromID(idMap)
			}
		}
	}

	if len(meta.ID2Label) == 0 && len(meta.Label2ID) > 0 {
		meta.ID2Label = labelsMapFromLabel2ID(meta.Label2ID)
	}
	if len(meta.Labels) == 0 && len(meta.ID2Label) > 0 {
		meta.Labels = labelsFromIDMapReverse(meta.ID2Label)
		meta.NumLabels = len(meta.Labels)
	}
	return meta, nil
}

func labelsFromIDMap(id2label map[string]string) []string {
	if len(id2label) == 0 {
		return nil
	}
	type entry struct {
		id    int
		label string
	}
	entries := make([]entry, 0, len(id2label))
	maxID := -1
	for k, v := range id2label {
		id, err := strconvAtoi(k)
		if err != nil {
			continue
		}
		entries = append(entries, entry{id: id, label: v})
		if id > maxID {
			maxID = id
		}
	}
	if maxID < 0 || len(entries) == 0 {
		return nil
	}
	labels := make([]string, maxID+1)
	for _, e := range entries {
		labels[e.id] = e.label
	}
	return labels
}

func labelsFromIDMapAny(id2label map[string]any) []string {
	if len(id2label) == 0 {
		return nil
	}
	type entry struct {
		id    int
		label string
	}
	entries := make([]entry, 0, len(id2label))
	maxID := -1
	for k, raw := range id2label {
		id, err := strconvAtoi(k)
		if err != nil {
			continue
		}
		lbl := strings.TrimSpace(fmt.Sprint(raw))
		entries = append(entries, entry{id: id, label: lbl})
		if id > maxID {
			maxID = id
		}
	}
	if maxID < 0 || len(entries) == 0 {
		return nil
	}
	labels := make([]string, maxID+1)
	for _, e := range entries {
		labels[e.id] = e.label
	}
	return labels
}

func labelsFromIDMapReverse(id2label map[int]string) []string {
	if len(id2label) == 0 {
		return nil
	}
	maxID := -1
	for id := range id2label {
		if id > maxID {
			maxID = id
		}
	}
	if maxID < 0 {
		return nil
	}
	labels := make([]string, maxID+1)
	for id, lbl := range id2label {
		labels[id] = lbl
	}
	return labels
}

func labelsMapFromID(id2label map[string]string) map[int]string {
	if len(id2label) == 0 {
		return nil
	}
	out := make(map[int]string, len(id2label))
	for k, v := range id2label {
		id, err := strconvAtoi(k)
		if err != nil {
			continue
		}
		out[id] = v
	}
	return out
}

func labelsMapFromIDAny(id2label map[string]any) map[int]string {
	if len(id2label) == 0 {
		return nil
	}
	out := make(map[int]string, len(id2label))
	for k, raw := range id2label {
		id, err := strconvAtoi(k)
		if err != nil {
			continue
		}
		out[id] = strings.TrimSpace(fmt.Sprint(raw))
	}
	return out
}

func labelsMapFromLabel2ID(label2id map[string]int) map[int]string {
	if len(label2id) == 0 {
		return nil
	}
	out := make(map[int]string, len(label2id))
	for lbl, id := range label2id {
		out[id] = lbl
	}
	return out
}

func newSpecialistSession(modelPath string, seqLen, numLabels int, outputDims []int64, intraThr, interThr int, tokenClassification bool, includeTokenType bool, outputName string) (*specialistSession, error) {
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
	var tokenType *ort.Tensor[int64]
	if includeTokenType {
		tokenType, err = ort.NewEmptyTensor[int64](inputShape)
		if err != nil {
			opts.Destroy()
			return nil, fmt.Errorf("allocate token_type_ids tensor: %w", err)
		}
	}

	outputShape := buildOutputShape(outputDims, seqLen, numLabels, tokenClassification)
	output, err := ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		opts.Destroy()
		return nil, fmt.Errorf("allocate output tensor: %w", err)
	}

	inputNames := []string{"input_ids", "attention_mask"}
	inputValues := []ort.Value{inputIDs, attnMask}
	if tokenType != nil {
		inputNames = append(inputNames, "token_type_ids")
		inputValues = append(inputValues, tokenType)
	}
	outName := outputName
	if outName == "" {
		outName = "logits"
	}
	session, err := ort.NewAdvancedSession(
		modelPath,
		inputNames,
		[]string{outName},
		inputValues,
		[]ort.Value{output},
		opts,
	)
	if err != nil {
		opts.Destroy()
		return nil, fmt.Errorf("create onnx session: %w", err)
	}
	opts.Destroy()

	return &specialistSession{
		session:       session,
		inputIDs:      inputIDs,
		attentionMask: attnMask,
		tokenTypeIDs:  tokenType,
		output:        output,
	}, nil
}

func strconvAtoi(v string) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, errors.New("empty")
	}
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, errors.New("non-digit")
		}
		n = n*10 + int(v[i]-'0')
	}
	return n, nil
}

func selectOutputInfo(modelPath string) (string, []int64, error) {
	_, outputs, err := ort.GetInputOutputInfoWithOptions(modelPath, nil)
	if err != nil {
		return "", nil, err
	}
	if len(outputs) == 0 {
		return "", nil, fmt.Errorf("no outputs found")
	}
	for _, out := range outputs {
		if strings.EqualFold(out.Name, "logits") {
			return out.Name, out.Dimensions, nil
		}
	}
	if len(outputs) == 1 {
		return outputs[0].Name, outputs[0].Dimensions, nil
	}
	return "", nil, fmt.Errorf("multiple outputs found without logits: %v", outputNames(outputs))
}

func buildOutputShape(dims []int64, seqLen, numLabels int, tokenClassification bool) ort.Shape {
	if len(dims) > 0 {
		shape := make([]int64, len(dims))
		for i, v := range dims {
			if v > 0 {
				shape[i] = v
				continue
			}
			if tokenClassification {
				if i == 1 {
					shape[i] = int64(seqLen)
				} else if i == 2 && numLabels > 0 {
					shape[i] = int64(numLabels)
				} else {
					shape[i] = 1
				}
			} else {
				if i == len(dims)-1 && numLabels > 0 {
					shape[i] = int64(numLabels)
				} else {
					shape[i] = 1
				}
			}
		}
		if len(shape) == 2 && !tokenClassification && numLabels > 0 {
			shape[1] = int64(numLabels)
		}
		if len(shape) == 3 && tokenClassification {
			if shape[1] == 0 {
				shape[1] = int64(seqLen)
			}
			if shape[2] == 0 && numLabels > 0 {
				shape[2] = int64(numLabels)
			}
		}
		return ort.Shape(shape)
	}
	if tokenClassification {
		return ort.NewShape(1, int64(seqLen), int64(numLabels))
	}
	return ort.NewShape(1, int64(numLabels))
}

func outputNames(outputs []ort.InputOutputInfo) []string {
	names := make([]string, 0, len(outputs))
	for _, out := range outputs {
		names = append(names, out.Name)
	}
	return names
}

func pickAttackClass(modelID string, meta specialistMeta, classCount int) (int, string) {
	if classCount <= 0 {
		classCount = meta.NumLabels
	}
	id2label := meta.ID2Label
	if len(id2label) == 0 && len(meta.Labels) > 0 {
		id2label = make(map[int]string, len(meta.Labels))
		for i, lbl := range meta.Labels {
			id2label[i] = lbl
		}
	}
	candidates := make([]int, 0, len(id2label))
	for idx := range id2label {
		candidates = append(candidates, idx)
	}
	sort.Ints(candidates)
	match := func(lbl string) bool {
		l := strings.ToLower(lbl)
		switch modelID {
		case "prompt_injection":
			return strings.Contains(l, "injection") || strings.Contains(l, "prompt_injection") || strings.Contains(l, "attack") || strings.Contains(l, "unsafe")
		case "jailbreak":
			return strings.Contains(l, "jailbreak") || strings.Contains(l, "attack") || strings.Contains(l, "unsafe")
		default:
			return strings.Contains(l, "attack") || strings.Contains(l, "unsafe")
		}
	}
	for _, idx := range candidates {
		if lbl, ok := id2label[idx]; ok && match(lbl) {
			if isSafeLabel(lbl) && classCount == 2 {
				alt := 1
				if idx == 1 {
					alt = 0
				}
				if altLbl, ok := id2label[alt]; ok {
					return alt, altLbl
				}
			}
			return idx, id2label[idx]
		}
	}
	if classCount == 2 {
		for _, idx := range candidates {
			lbl := strings.ToLower(id2label[idx])
			if lbl == "label_0" || lbl == "label_1" || isSafeLabel(lbl) {
				continue
			}
			return idx, id2label[idx]
		}
		if lbl, ok := id2label[1]; ok {
			redact.Logf("strajaguard: warning no attack label match for %s; using index 1 labels=%v", modelID, id2label)
			return 1, lbl
		}
		if lbl, ok := id2label[0]; ok {
			redact.Logf("strajaguard: warning no attack label match for %s; using index 0 labels=%v", modelID, id2label)
			return 0, lbl
		}
		redact.Logf("strajaguard: warning no attack label match for %s; using default index 1 labels=%v", modelID, id2label)
		return 1, ""
	}
	if lbl, ok := id2label[1]; ok {
		redact.Logf("strajaguard: warning no attack label match for %s; using index 1 labels=%v", modelID, id2label)
		return 1, lbl
	}
	redact.Logf("strajaguard: warning no attack label match for %s; using default index 1 labels=%v", modelID, id2label)
	return 1, ""
}

func isSafeLabel(lbl string) bool {
	l := strings.ToLower(lbl)
	return strings.Contains(l, "safe") || strings.Contains(l, "benign")
}

func sequenceScore(raw []float32, numLabels int, dims []int64, attackIdx int, attackLabel, modelID string) (float32, []float32, int, string) {
	classCount := classCountFromShape(numLabels, dims, len(raw))
	logits := selectLogitsRow(raw, classCount)
	if classCount <= 1 {
		score := sigmoid(logits[0])
		return score, []float32{score}, 0, attackLabel
	}
	probs := softmax(logits)
	idx := attackIdx
	if idx < 0 || idx >= len(probs) {
		idx = defaultAttackIndex(probs, attackLabel)
	}
	return probs[idx], probs, idx, attackLabel
}

func classCountFromShape(numLabels int, dims []int64, rawLen int) int {
	if len(dims) > 0 {
		last := dims[len(dims)-1]
		if last > 0 {
			return int(last)
		}
	}
	if numLabels > 0 {
		return numLabels
	}
	if rawLen > 0 {
		return rawLen
	}
	return 1
}

func selectLogitsRow(raw []float32, classCount int) []float32 {
	if classCount <= 0 {
		return raw
	}
	if len(raw) <= classCount {
		return raw
	}
	return raw[:classCount]
}

func softmax(logits []float32) []float32 {
	if len(logits) == 0 {
		return nil
	}
	maxVal := logits[0]
	for _, v := range logits[1:] {
		if v > maxVal {
			maxVal = v
		}
	}
	sum := 0.0
	out := make([]float32, len(logits))
	for i, v := range logits {
		exp := math.Exp(float64(v - maxVal))
		out[i] = float32(exp)
		sum += exp
	}
	if sum == 0 {
		return out
	}
	for i := range out {
		out[i] = float32(float64(out[i]) / sum)
	}
	return out
}

func sigmoid(v float32) float32 {
	return float32(1.0 / (1.0 + math.Exp(-float64(v))))
}

func defaultAttackIndex(probs []float32, attackLabel string) int {
	if len(probs) == 2 {
		if isSafeLabel(attackLabel) {
			return 0
		}
		return 1
	}
	if len(probs) > 1 {
		return 1
	}
	return 0
}

func debugML() bool {
	return strings.TrimSpace(os.Getenv("STRAJA_DEBUG_ML")) == "1"
}

func logTokenization(modelID, requestID string, maxTokens int, inputIDs, attn []int64) {
	if !debugML() {
		return
	}
	count := 0
	for _, v := range attn {
		if v > 0 {
			count++
		}
	}
	preview := inputIDs
	if len(preview) > 8 {
		preview = preview[:8]
	}
	redact.Logf("strajaguard debug ml: request_id=%s model=%s max_tokens=%d token_count=%d first_ids=%v", requestID, modelID, maxTokens, count, preview)
}

func logSequenceDebug(modelID, requestID string, logits []float32, probs []float32, attackIdx int, attackLabel string, score float32) {
	if !debugML() {
		return
	}
	logVec := logits
	if len(logVec) > 8 {
		logVec = logVec[:8]
	}
	probVec := probs
	if len(probVec) > 8 {
		probVec = probVec[:8]
	}
	redact.Logf("strajaguard debug ml: request_id=%s model=%s logits=%v probs=%v attack_idx=%d attack_label=%s score=%.4f", requestID, modelID, logVec, probVec, attackIdx, attackLabel, score)
}

func specialistNeedsTokenTypeIDs(modelDir string) bool {
	cfgPath := filepath.Join(modelDir, "config.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return false
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false
	}
	if val, ok := cfg["type_vocab_size"]; ok {
		switch num := val.(type) {
		case float64:
			return num > 0
		case int:
			return num > 0
		case int64:
			return num > 0
		}
	}
	return false
}
