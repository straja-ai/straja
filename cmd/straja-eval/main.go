package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/strajaguard"
)

type prompt struct {
	ID       string `json:"id"`
	Text     string `json:"text"`
	Label    int    `json:"label"`    // 0 benign, 1 attack
	Category string `json:"category"` // optional; if empty, inferred by file arg
}

type detectorOut struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind,omitempty"`
	ModelRef  string   `json:"model_ref,omitempty"`
	Score     *float32 `json:"score,omitempty"`
	LatencyMs float64  `json:"latency_ms,omitempty"`
	Error     string   `json:"error,omitempty"`
	Version   string   `json:"version,omitempty"`
}

type resultLine struct {
	PromptID     string        `json:"prompt_id"`
	Category     string        `json:"category"`
	Label        int           `json:"label"`
	Text         string        `json:"text"`
	Ensemble     any           `json:"ensemble"`
	Detectors    []detectorOut `json:"detectors"`
	TotalMs      float64       `json:"total_ms"`
	BundleDir    string        `json:"bundle_dir"`
	ConfigSource string        `json:"config_source"`
}

type metrics struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	TN int `json:"tn"`
	FN int `json:"fn"`

	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	Accuracy  float64 `json:"accuracy"`

	LatencyP50 float64 `json:"latency_p50_ms"`
	LatencyP95 float64 `json:"latency_p95_ms"`
	LatencyMax float64 `json:"latency_max_ms"`
	LatencyAvg float64 `json:"latency_avg_ms"`
	N          int     `json:"n"`
}

type evalRow struct {
	label     int
	score     float32
	latencyMs float64
}

type detectorEvalRow struct {
	label     int
	score     float32
	latencyMs float64
	valid     bool
}

type detectorMetrics struct {
	NTotal     int     `json:"n_total"`
	NValid     int     `json:"n_valid"`
	NInvalid   int     `json:"n_invalid"`
	TP         int     `json:"tp"`
	FP         int     `json:"fp"`
	TN         int     `json:"tn"`
	FN         int     `json:"fn"`
	Precision  float64 `json:"precision"`
	Recall     float64 `json:"recall"`
	F1         float64 `json:"f1"`
	Accuracy   float64 `json:"accuracy"`
	LatencyP50 float64 `json:"latency_p50_ms"`
	LatencyP95 float64 `json:"latency_p95_ms"`
	LatencyMax float64 `json:"latency_max_ms"`
	LatencyAvg float64 `json:"latency_avg_ms"`
}

func pct(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Round((p / 100.0) * float64(len(sorted)-1)))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func main() {
	bundleDir := flag.String("bundle", "", "path to bundle root or versioned dir (required)")
	cfgPath := flag.String("specialists-config", "", "path to strajaguard_specialists.yaml (optional; default uses embedded)")
	seqLen := flag.Int("seq-len", 256, "sequence length")
	threshold := flag.Float64("threshold", 0.8, "attack threshold")
	intra := flag.Int("intra", 4, "intra threads")
	inter := flag.Int("inter", 1, "inter threads")
	maxSessions := flag.Int("max-sessions", 1, "max sessions")
	showText := flag.Bool("show-text", true, "include prompt text in per-prompt output")
	progressEvery := flag.Int("progress-every", 25, "print progress every N prompts (0 disables)")
	flag.Parse()

	if strings.TrimSpace(*bundleDir) == "" {
		log.Fatalf("-bundle is required")
	}
	inputs := flag.Args()
	if len(inputs) == 0 {
		log.Fatalf("provide one or more prompt jsonl files as args")
	}

	rt := strajaguard.ResolveRuntime(strajaguard.RuntimeConfig{MaxSessions: *maxSessions, IntraThreads: *intra, InterThreads: *inter})
	engine, source, err := strajaguard.LoadSpecialistsEngine(*bundleDir, *seqLen, rt, *cfgPath)
	if err != nil {
		log.Fatalf("LoadSpecialistsEngine: %v", err)
	}

	// Run warmup.
	_, _ = engine.Warmup("how are you?")

	perCat := map[string][]evalRow{}
	perDetector := map[string]map[string][]detectorEvalRow{}
	totalPrompts := countNonEmptyJSONLLines(inputs)
	processed := 0

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)

	for _, path := range inputs {
		cat := ""
		base := strings.ToLower(filepath.Base(path))
		switch {
		case strings.Contains(base, "prompt_injection"):
			cat = "prompt_injection"
		case strings.Contains(base, "jailbreak"):
			cat = "jailbreak"
		}

		f, err := os.Open(path)
		if err != nil {
			log.Fatalf("open %s: %v", path, err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var p prompt
			if err := json.Unmarshal([]byte(line), &p); err != nil {
				log.Fatalf("decode %s: %v", path, err)
			}
			if p.Category == "" {
				p.Category = cat
			}
			if p.Category == "" {
				log.Fatalf("prompt %s missing category and cannot infer from filename %s", p.ID, path)
			}

			start := time.Now()
			ctx := strajaguard.WithRequestID(context.Background(), p.ID)
			res, err := engine.AnalyzeText(ctx, p.Text)
			elapsed := float64(time.Since(start)) / float64(time.Millisecond)
			if err != nil {
				log.Fatalf("AnalyzeText %s: %v", p.ID, err)
			}

			score := float32(0)
			var ens any
			var dets []detectorOut
			switch p.Category {
			case "prompt_injection":
				d := res.Detections.PromptInjection
				if d != nil {
					score = d.Ensemble.Score
					ens = d.Ensemble
					for _, r := range d.Detectors {
						dets = append(dets, detectorOut(r))
					}
				}
			case "jailbreak":
				d := res.Detections.Jailbreak
				if d != nil {
					score = d.Ensemble.Score
					ens = d.Ensemble
					for _, r := range d.Detectors {
						dets = append(dets, detectorOut(r))
					}
				}
			default:
				log.Fatalf("unknown category %s", p.Category)
			}

			// Sort detectors for stable output.
			sort.Slice(dets, func(i, j int) bool { return dets[i].ID < dets[j].ID })

			perCat[p.Category] = append(perCat[p.Category], evalRow{
				label:     p.Label,
				score:     score,
				latencyMs: elapsed,
			})
			if _, ok := perDetector[p.Category]; !ok {
				perDetector[p.Category] = map[string][]detectorEvalRow{}
			}
			for _, d := range dets {
				row := detectorEvalRow{
					label:     p.Label,
					latencyMs: d.LatencyMs,
					valid:     strings.TrimSpace(d.Error) == "" && d.Score != nil,
				}
				if d.Score != nil {
					row.score = *d.Score
				}
				perDetector[p.Category][d.ID] = append(perDetector[p.Category][d.ID], row)
			}

			out := resultLine{
				PromptID:     p.ID,
				Category:     p.Category,
				Label:        p.Label,
				Ensemble:     ens,
				Detectors:    dets,
				TotalMs:      elapsed,
				BundleDir:    *bundleDir,
				ConfigSource: source,
			}
			if *showText {
				out.Text = p.Text
			}
			if err := enc.Encode(out); err != nil {
				log.Fatalf("encode: %v", err)
			}
			processed++
			if *progressEvery > 0 && processed%*progressEvery == 0 {
				if totalPrompts > 0 {
					pct := (float64(processed) / float64(totalPrompts)) * 100.0
					fmt.Fprintf(os.Stderr, "PROGRESS processed=%d/%d (%.1f%%)\n", processed, totalPrompts, pct)
				} else {
					fmt.Fprintf(os.Stderr, "PROGRESS processed=%d\n", processed)
				}
			}
		}
		_ = f.Close()
		if err := scanner.Err(); err != nil {
			log.Fatalf("scan %s: %v", path, err)
		}
	}
	finalAlreadyPrinted := *progressEvery > 0 && processed > 0 && processed%*progressEvery == 0
	if !finalAlreadyPrinted {
		if totalPrompts > 0 {
			fmt.Fprintf(os.Stderr, "PROGRESS processed=%d/%d (100.0%%)\n", processed, totalPrompts)
		} else {
			fmt.Fprintf(os.Stderr, "PROGRESS processed=%d\n", processed)
		}
	}

	// Summary metrics to stderr (so stdout stays JSONL).
	categories := make([]string, 0, len(perCat))
	for cat := range perCat {
		categories = append(categories, cat)
	}
	sort.Strings(categories)
	for _, cat := range categories {
		rows := perCat[cat]
		m := computeMetrics(rows, *threshold)
		b, _ := json.Marshal(m)
		fmt.Fprintf(os.Stderr, "METRICS category=%s threshold=%.2f %s\n", cat, *threshold, string(b))
		fmt.Fprintf(
			os.Stderr,
			"SUMMARY category=%s threshold=%.2f n=%d TP=%d FP=%d TN=%d FN=%d precision=%.4f recall=%.4f f1=%.4f accuracy=%.4f latency_ms(avg=%.2f,p50=%.2f,p95=%.2f,max=%.2f)\n",
			cat,
			*threshold,
			m.N,
			m.TP,
			m.FP,
			m.TN,
			m.FN,
			m.Precision,
			m.Recall,
			m.F1,
			m.Accuracy,
			m.LatencyAvg,
			m.LatencyP50,
			m.LatencyP95,
			m.LatencyMax,
		)

		detByID := perDetector[cat]
		detIDs := make([]string, 0, len(detByID))
		for id := range detByID {
			detIDs = append(detIDs, id)
		}
		sort.Strings(detIDs)
		for _, detID := range detIDs {
			dRows := detByID[detID]
			validRows := make([]evalRow, 0, len(dRows))
			invalid := 0
			for _, r := range dRows {
				if !r.valid {
					invalid++
					continue
				}
				validRows = append(validRows, evalRow{
					label:     r.label,
					score:     r.score,
					latencyMs: r.latencyMs,
				})
			}
			dm := computeMetrics(validRows, *threshold)
			dp := detectorMetrics{
				NTotal:     len(dRows),
				NValid:     dm.N,
				NInvalid:   invalid,
				TP:         dm.TP,
				FP:         dm.FP,
				TN:         dm.TN,
				FN:         dm.FN,
				Precision:  dm.Precision,
				Recall:     dm.Recall,
				F1:         dm.F1,
				Accuracy:   dm.Accuracy,
				LatencyP50: dm.LatencyP50,
				LatencyP95: dm.LatencyP95,
				LatencyMax: dm.LatencyMax,
				LatencyAvg: dm.LatencyAvg,
			}
			db, _ := json.Marshal(dp)
			fmt.Fprintf(os.Stderr, "DETECTOR_METRICS category=%s detector=%s threshold=%.2f %s\n", cat, detID, *threshold, string(db))
			fmt.Fprintf(
				os.Stderr,
				"SUMMARY_DETECTOR category=%s detector=%s threshold=%.2f n_total=%d n_valid=%d n_invalid=%d TP=%d FP=%d TN=%d FN=%d precision=%.4f recall=%.4f f1=%.4f accuracy=%.4f latency_ms(avg=%.2f,p50=%.2f,p95=%.2f,max=%.2f)\n",
				cat,
				detID,
				*threshold,
				dp.NTotal,
				dp.NValid,
				dp.NInvalid,
				dp.TP,
				dp.FP,
				dp.TN,
				dp.FN,
				dp.Precision,
				dp.Recall,
				dp.F1,
				dp.Accuracy,
				dp.LatencyAvg,
				dp.LatencyP50,
				dp.LatencyP95,
				dp.LatencyMax,
			)
		}
	}
}

func computeMetrics(rows []evalRow, threshold float64) metrics {
	var tp, fp, tn, fn int
	lats := make([]float64, 0, len(rows))
	var sum float64
	for _, r := range rows {
		pred := 0
		if float64(r.score) >= threshold {
			pred = 1
		}
		if pred == 1 && r.label == 1 {
			tp++
		} else if pred == 1 && r.label == 0 {
			fp++
		} else if pred == 0 && r.label == 0 {
			tn++
		} else {
			fn++
		}
		lats = append(lats, r.latencyMs)
		sum += r.latencyMs
	}
	sort.Float64s(lats)
	prec := 0.0
	rec := 0.0
	if tp+fp > 0 {
		prec = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		rec = float64(tp) / float64(tp+fn)
	}
	f1 := 0.0
	if prec+rec > 0 {
		f1 = 2 * prec * rec / (prec + rec)
	}
	acc := 0.0
	if len(rows) > 0 {
		acc = float64(tp+tn) / float64(tp+tn+fp+fn)
	}
	avg := 0.0
	if len(rows) > 0 {
		avg = sum / float64(len(rows))
	}
	return metrics{
		TP:         tp,
		FP:         fp,
		TN:         tn,
		FN:         fn,
		Precision:  prec,
		Recall:     rec,
		F1:         f1,
		Accuracy:   acc,
		LatencyP50: pct(lats, 50),
		LatencyP95: pct(lats, 95),
		LatencyMax: pct(lats, 100),
		LatencyAvg: avg,
		N:          len(rows),
	}
}

func countNonEmptyJSONLLines(paths []string) int {
	total := 0
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "" {
				continue
			}
			total++
		}
		_ = f.Close()
	}
	return total
}
