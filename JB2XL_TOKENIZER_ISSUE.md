# jb_2xl tokenizer/scoring issue — handoff note

## Background

We introduced a second jailbreak detector (`jb_2xl`, `qwen_next_token`) and aggregate with an ensemble.
In production and in local golden-prompt evals, jailbreak behavior became unstable:

- early phase: many benign prompts blocked (high false positives)
- after partial fixes: prompt-injection looked good, but jailbreak recall stayed poor on policy-override prompts

A dedicated eval tool was added (`cmd/straja-eval`) to print, per prompt:

- ensemble score/decision
- per-detector scores (`jb_v1`, `jb_2xl`, `pi_deberta_v3`)
- per-detector `latency_ms`
- total latency
- summary metrics (precision/recall/F1/accuracy + latency p50/p95/max/avg)

## Current observed state

- `prompt_injection` on the current golden prompts: excellent (F1 ~ 1.0)
- `jailbreak` on the current golden prompts: poor (low recall at threshold 0.8)
- `jb_2xl` scores are inconsistent with expected model-card-level behavior

## Exact cause (best current evidence)

The most likely root cause is **tokenizer mismatch for Qwen BPE path in Go runtime**.

Evidence:

1. HF tokenizer (`tokenizers`/`transformers`) for `jailbreak2xl/tokenizer.json` + prompt template + `"how are you?"`
   yields **33 active tokens**.
2. Go runtime tokenizer path currently yields a very different sequence/count (parity test failing).
3. `jb_2xl` decisions are highly sensitive to tokenization/label alignment and diverge from expected behavior.

Important detail:

- `jailbreak2xl/tokenizer.json` uses:
  - normalizer: NFC
  - pre-tokenizer: `Sequence(Split(regex=...), ByteLevel(...))`
- current Go BPE implementation uses a simplified/hardcoded regex path and does not faithfully reproduce tokenizer.json behavior.
- the tokenizer.json Split regex includes constructs like negative lookahead `(?!\S)` which Go regexp does not support directly.

## Secondary issue discovered/fixed

`jb_2xl` latency was missing in activation payloads because `Evaluate` used defer + non-named return.
This was fixed by switching to named return so deferred latency assignment is preserved.

## What is likely the correct solution

1. **Implement exact pre-tokenizer parity for Qwen path** in Go:
   - do not rely on the current hardcoded GPT-style regex approximation.
   - parse/apply tokenizer.json pre-tokenizer semantics (or implement equivalent manual splitter for unsupported regex features).
2. Keep ByteLevel + BPE behavior aligned with tokenizer.json.
3. Add strict parity tests against known HF token IDs for several template+prompt fixtures.
4. Re-run `straja-eval` golden suite and verify jailbreak metrics recover.

## How to test

### A) Tokenizer parity (must pass before anything else)

```bash
cd straja
STRAJA_INTEGRATION=1 go test ./internal/strajaguard -run TestTokenizer_Qwen_Parity_HowAreYou -count=1
```

Expected: pass with exact token ID match vs HF reference IDs in the test.

### B) Golden suite with per-model scores + latency

```bash
cd straja
set -a && source .env && set +a

go run ./cmd/straja-eval \
  -bundle /path/to/exported_bundle \
  -specialists-config ./configs/strajaguard_specialists.yaml \
  -threshold 0.8 \
  ../straja-intel-guard/tests/prompts_prompt_injection.jsonl \
  ../straja-intel-guard/tests/prompts_jailbreak.jsonl
```

Expected output:

- JSON lines per prompt with detector scores + latency
- METRICS lines per category

### C) Local export sanity (intel repo)

```bash
cd straja-intel-guard
source .venv/bin/activate
make export-specialists SPECIALISTS_OUTPUT=/tmp/sg_export_eval
```

Check produced files include expected model artifacts; runtime should prefer `model.int8.onnx` where present.

## Notes on thresholds

User explicitly requested **no threshold lowering** during this debugging cycle.
So verification should be done with current thresholds (especially jailbreak block threshold 0.8), and fixes should focus on tokenizer/model-path correctness.

## Files touched in this WIP commit

- `internal/strajaguard/detector_qwen_next_token.go`
- `internal/strajaguard/integration_jailbreak_test.go`
- `internal/strajaguard/tokenizer_bpe.go`
- `internal/strajaguard/tokenizer_qwen_parity_test.go` (new)
- `JB2XL_TOKENIZER_ISSUE.md` (this document)
