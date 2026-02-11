package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/straja-ai/straja/internal/strajaguard"
)

type row struct {
	text  string
	label int
}

type pred struct {
	label int
	pi    int
	jb    int
	err   error
}

type stats struct {
	TP int
	FP int
	TN int
	FN int
}

func (s *stats) add(label, prediction int) {
	switch {
	case label == 1 && prediction == 1:
		s.TP++
	case label == 0 && prediction == 1:
		s.FP++
	case label == 0 && prediction == 0:
		s.TN++
	case label == 1 && prediction == 0:
		s.FN++
	}
}

func (s stats) precision() float64 {
	d := s.TP + s.FP
	if d == 0 {
		return 0
	}
	return float64(s.TP) / float64(d)
}

func (s stats) recall() float64 {
	d := s.TP + s.FN
	if d == 0 {
		return 0
	}
	return float64(s.TP) / float64(d)
}

func (s stats) f1() float64 {
	p := s.precision()
	r := s.recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func main() {
	csvPath := flag.String("csv", "/Users/sorinmanole/Downloads/test.csv", "CSV file with text,label")
	bundleRoot := flag.String("bundle-root", "/Users/sorinmanole/straja-work-suite/straja/intel/strajaguard_v1_specialists", "bundle root")
	cfgPath := flag.String("config", "/Users/sorinmanole/straja-work-suite/straja/configs/strajaguard_specialists.yaml", "specialists config")
	workers := flag.Int("workers", 4, "number of concurrent workers")
	threshold := flag.Float64("threshold", 0.8, "score threshold")
	progressEvery := flag.Int("progress-every", 500, "print progress every N processed rows (0 disables)")
	flag.Parse()

	if *workers <= 0 {
		*workers = 1
	}

	bundleDir := *bundleRoot
	if st, err := strajaguard.LoadBundleState(*bundleRoot); err == nil && strings.TrimSpace(st.CurrentVersion) != "" {
		bundleDir = filepath.Join(*bundleRoot, st.CurrentVersion)
	}

	rt := strajaguard.ResolveRuntime(strajaguard.RuntimeConfig{MaxSessions: *workers, IntraThreads: 4, InterThreads: 1})
	eng, source, err := strajaguard.LoadSpecialistsEngine(bundleDir, 256, rt, *cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LoadSpecialistsEngine: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Open(*csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open csv: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	head, err := r.Read()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read header: %v\n", err)
		os.Exit(1)
	}
	textIdx, labelIdx := -1, -1
	for i, h := range head {
		hh := strings.ToLower(strings.TrimSpace(h))
		if hh == "text" {
			textIdx = i
		}
		if hh == "label" {
			labelIdx = i
		}
	}
	if textIdx < 0 || labelIdx < 0 {
		fmt.Fprintf(os.Stderr, "missing text,label columns\n")
		os.Exit(1)
	}

	jobs := make(chan row, *workers*4)
	outs := make(chan pred, *workers*4)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := range jobs {
				ctx := strajaguard.WithRequestID(context.Background(), fmt.Sprintf("csv-%d", workerID))
				res, err := eng.AnalyzeText(ctx, j.text)
				if err != nil {
					outs <- pred{label: j.label, err: err}
					continue
				}

				piScore := float32(0)
				if res != nil && res.Detections != nil && res.Detections.PromptInjection != nil {
					piScore = res.Detections.PromptInjection.Ensemble.Score
				}
				jbScore := float32(0)
				if res != nil && res.Detections != nil && res.Detections.Jailbreak != nil {
					jbScore = res.Detections.Jailbreak.Ensemble.Score
				}

				piPred := 0
				if float64(piScore) >= *threshold {
					piPred = 1
				}
				jbPred := 0
				if float64(jbScore) >= *threshold {
					jbPred = 1
				}
				outs <- pred{label: j.label, pi: piPred, jb: jbPred}
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(outs)
	}()

	processed := 0
	skipped := 0
	go func() {
		defer close(jobs)
		for {
			rec, err := r.Read()
			if err == io.EOF {
				return
			}
			if err != nil {
				skipped++
				continue
			}
			if textIdx >= len(rec) || labelIdx >= len(rec) {
				skipped++
				continue
			}
			text := strings.TrimSpace(rec[textIdx])
			labelRaw := strings.ToLower(strings.TrimSpace(rec[labelIdx]))
			if text == "" {
				skipped++
				continue
			}
			var y int
			switch labelRaw {
			case "jailbreak":
				y = 1
			case "benign":
				y = 0
			default:
				skipped++
				continue
			}
			processed++
			if *progressEvery > 0 && processed%*progressEvery == 0 {
				fmt.Fprintf(os.Stderr, "progress processed=%d skipped=%d\n", processed, skipped)
			}
			jobs <- row{text: text, label: y}
		}
	}()

	var piStats stats
	var jbStats stats
	errors := 0
	for o := range outs {
		if o.err != nil {
			errors++
			continue
		}
		piStats.add(o.label, o.pi)
		jbStats.add(o.label, o.jb)
	}

	fmt.Printf("bundle_dir=%s\n", bundleDir)
	fmt.Printf("config_source=%s\n", source)
	fmt.Printf("rows_processed=%d rows_skipped=%d inference_errors=%d threshold=%.2f\n", processed, skipped, errors, *threshold)
	fmt.Printf("PI tp=%d fp=%d tn=%d fn=%d precision=%.6f recall=%.6f f1=%.6f\n", piStats.TP, piStats.FP, piStats.TN, piStats.FN, piStats.precision(), piStats.recall(), piStats.f1())
	fmt.Printf("JB tp=%d fp=%d tn=%d fn=%d precision=%.6f recall=%.6f f1=%.6f\n", jbStats.TP, jbStats.FP, jbStats.TN, jbStats.FN, jbStats.precision(), jbStats.recall(), jbStats.f1())
}
