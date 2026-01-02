# Straja Gateway

🚧 **Straja** is a local, OpenAI-compatible AI gateway that runs *inside your infrastructure*.

It gives you:

- 🔐 **Security** – PII / secrets detection, basic prompt-injection & jailbreak heuristics  
- 🕵️ **Privacy** – Apps never see upstream provider keys  
- 📊 **Observability** – Structured activation events for every request  
- 🔀 **Routing** – Projects mapped to providers (OpenAI today, more later)  
- 🧪 **Drop-in DX** – Same OpenAI SDKs and request shapes, just a different base URL + key  

---

## 🚀 Quick Start (recommended: prebuilt binary)

This is the **happy path** for most users: download the binary, configure one provider, and send a request.

### 1. Download the binary

```bash
curl -LO https://github.com/straja-ai/straja/releases/latest/download/straja
chmod +x straja
```

### 2. Set your provider API key

The provider key never appears in your application code. Straja reads it from an environment variable.

```bash
export OPENAI_API_KEY="sk-..."   # your real OpenAI key
```

> In production you typically set this in a systemd unit, container env, or a secrets manager.

### 3. Create `straja.yaml`

Minimal single-provider config:

```yaml
server:
  addr: ":8080"

default_provider: "openai_default"

providers:
  openai_default:
    type: "openai"
    base_url: "https://api.openai.com/v1"
    api_key_env: "OPENAI_API_KEY"  # Straja reads this from the environment

projects:
  - id: "default"
    provider: "openai_default"
    api_keys:
      - "local-dev-key-123"
```

### 4. Run Straja

```bash
./straja --config straja.yaml
```

### 5. Test a request

```bash
curl -X POST http://localhost:8080/v1/chat/completions   -H "Content-Type: application/json"   -H "Authorization: Bearer local-dev-key-123"   -d '{
    "model": "gpt-4.1-mini",
    "messages": [{ "role": "user", "content": "Hello from Straja!" }]
  }'
```

You should see an OpenAI-compatible JSON response.

---

## 🐳 Docker

Run Straja in a container, mounting your config and giving the runtime writable bundle dirs. The image expects:
- Config at `/etc/straja/straja.yaml`
- Intel dir at `/var/lib/straja/intel`
- Bundle cache at `/var/lib/straja/bundles`

Quick start (local build + sanity check):
```bash
# build multi-arch distroless image tagged straja:local
make docker-build

# run it with mounted config + writable cache dirs (adjust host port if 8080 is busy)
docker run --rm \
  -p 8080:8080 \
  -v "$(pwd)/straja.yaml:/etc/straja/straja.yaml:ro" \
  -v "$(pwd)/intel:/var/lib/straja/intel" \
  -v "$(pwd)/bundles:/var/lib/straja/bundles" \
  -e STRAJA_INTEL_DIR="/var/lib/straja/intel" \
  -e STRAJA_BUNDLE_CACHE_DIR="/var/lib/straja/bundles" \
  -e STRAJA_BUNDLE_DIR="/var/lib/straja/bundles/strajaguard_v1" \
  -e OPENAI_API_KEY="sk-..." \
  -e STRAJA_LICENSE_KEY="your-license" \
  straja:local
```

If you prefer a one-liner that waits for readiness, use `make docker-run` (same mounts, assumes port 8080).

Your apps still talk to `http://host:8080/v1` and use **project keys**, not provider keys.

**Do not bake API keys or license keys into the image.** Keep `straja.yaml` and secrets mounted or injected via env/secrets manager so images stay reusable and safe.

---

## 🔒 Hardening & production defaults

- Secrets are redacted from logs/activations (bearer/API keys, license keys, bundle URLs).
- Startup validation fails fast on missing addr/providers/projects, bad provider URLs, or private networks unless `allow_private_networks: true` for dev/mock.
- Provider API keys: env wins (`api_key_env`); optional `api_key` is a local fallback. License keys are taken from `license_key_env` (placeholders in YAML are ignored); values are never logged.
- Request guards: defaults cap body (2MiB), messages (64), and total content length (~32k chars). Oversized requests return 400/413 and are not forwarded upstream.
- Model allowlists: set `allowed_models` per project or provider to block arbitrary proxying; unknown models return 400 `invalid_request_error`.
- StrajaGuard bundles: paths are confined to the bundle dir; traversal/absolute paths are rejected. Failed updates keep the previous bundle; without a previous bundle, Straja falls back to regex-only unless `require_ml=true`.

Recommended:
- Keep provider URLs HTTPS; leave `allow_private_networks` off except for mock/local testing.
- Store project API keys in config, but inject provider/license keys via env or secret store.
- You can override bundle/intel paths without editing YAML by setting:
  - `STRAJA_INTEL_DIR` for StrajaGuard bundle root
  - `STRAJA_BUNDLE_DIR` for the security bundle dir (defaults to `<intel_dir>/strajaguard_v1`)
  - `STRAJA_BUNDLE_CACHE_DIR` for the bundle cache dir
- Tune `server.max_request_body_bytes`, `max_messages`, and `max_total_message_chars` for your traffic profile.

### License key configuration
- Use a single license key for both Intelligence and StrajaGuard. Precedence: env `STRAJA_LICENSE_KEY` (via `intelligence.license_key_env`) → `intel.strajaguard_v1.license_key` → `intelligence.license_key` (placeholders are ignored).
- Recommendation: set the env var and keep YAML keys empty in production.
- On network outages during validation, Straja keeps running with the last verified bundle and reports `strajaguard_status=offline_cached_bundle`.

### StrajaGuard licensing & bundles
- One license key (`STRAJA_LICENSE_KEY`) is used for StrajaGuard validation/update. Env wins; placeholders in YAML are ignored.
- Runtime behavior (matching the server state machine):

| Case | Behavior |
| --- | --- |
| No license key resolved (empty env + no real YAML key) | StrajaGuard ML disabled; runs regex-only; status `disabled_missing_license`. |
| Invalid license (online validate returns non-network error/status) | StrajaGuard ML disabled; cached bundle is not loaded; regex-only; status `disabled_invalid_license`. |
| Online validate fails with networky error (timeout/DNS/refused/502/503) | If a cached bundle verifies, StrajaGuard ML loads from disk; status `offline_cached_bundle`. Otherwise regex-only. |
| Cached bundle integrity fails | Do not load ML; stay regex-only; status `disabled_invalid_bundle` (or `disabled_missing_bundle` if nothing cached). |

- Operators can see these statuses via activation events (`intel_status`, `strajaguard_status`, `intel_bundle_version`, `intel_last_validated_at`) and `/readyz` (fields `status`, `mode`, `active_bundle_version`, `reason`, `intel_status`, `strajaguard_status`, `intel_last_validated_at`).
- To force a refresh, delete the bundle cache directory (default `./intel/strajaguard_v1`) or bump version; Straja will re-validate and re-download on next start.

---

## 💻 Running from source (Go dev flow)

For contributors or teams who want to run Straja from source.

### StrajaGuard ML dependency

The optional StrajaGuard v1 classifier runs locally via ONNX Runtime. Without the ONNX Runtime shared library, Straja falls back to regex-only detection and logs:

```
StrajaGuard ML disabled: ONNX Runtime not found (running regex-only).
To enable, install ONNX Runtime and restart. See README -> "StrajaGuard ML dependency".
```

Install ONNX Runtime:
- macOS (Homebrew): `brew install onnxruntime`
- Ubuntu/Debian: `sudo apt-get update && sudo apt-get install onnxruntime`
- Fedora/RHEL/CentOS: `sudo dnf install onnxruntime` or `sudo yum install onnxruntime`
- Windows (winget): `winget install onnxruntime`

If you install to a non-standard path, set `ONNXRUNTIME_SHARED_LIBRARY_PATH` to the full path of the shared library (e.g., `/opt/homebrew/lib/libonnxruntime.dylib` or `/usr/local/lib/libonnxruntime.so`) and restart Straja.

### 1. Clone the repo

```bash
git clone https://github.com/straja-ai/straja.git
cd straja
```

### 2. Create a `.env` file (not committed)

`.env` is gitignored. Put provider keys and other local-only settings here:

```bash
# if you have an example, otherwise just create .env
cp .env.example .env  # optional
```

Edit `.env`:

```env
OPENAI_API_KEY=sk-...
# add other provider keys later as needed
```

### 3. Create `straja.yaml` (same as in Quick Start)

```yaml
server:
  addr: ":8080"

default_provider: "openai_default"

providers:
  openai_default:
    type: "openai"
    base_url: "https://api.openai.com/v1"
    api_key_env: "OPENAI_API_KEY"

projects:
  - id: "default"
    provider: "openai_default"
    api_keys:
      - "local-dev-key-123"
```

### 4. Use the Makefile

```bash
# Build the binary into ./bin/straja
make build

# Run Straja with config
make run

# Run tests
make test

# Basic lint (go vet)
make lint

# Format Go files
make fmt

# Tidy Go modules
make tidy
```

If you prefer, you can also run the binary with `.env` in one shot:

```bash
env $(cat .env | xargs) ./bin/straja --config straja.yaml
```

---

## ⚙️ Configuration Reference (`straja.yaml`)

Full example:

```yaml
server:
  addr: ":8080"

default_provider: "openai_default"

providers:
  openai_default:
    type: "openai"
    base_url: "https://api.openai.com/v1"
    api_key_env: "OPENAI_API_KEY"

projects:
  - id: "default"
    provider: "openai_default"
    api_keys:
      - "local-dev-key-123"

logging:
  activation_level: "redacted"  # "metadata" | "redacted" | "full"

policy:
  banned_words: "block"         # block | log | ignore | redact
  pii: "block"
  injection: "block"
  prompt_injection: "block"
  jailbreak: "block"
  toxicity: "log"
  banned_words_list:
    - "blocked_test"
    - "forbidden"
  pii_entities:
    email: true
    phone: true
    credit_card: true
    iban: true
    tokens: true
```

### Providers

Each provider entry defines:

- `type` – e.g. `"openai"`  
- `base_url` – upstream endpoint  
- `api_key_env` – name of the env var holding the provider key (e.g. `OPENAI_API_KEY`)  

Straja **never** stores provider keys in the config file itself.

### Projects

Projects map *application keys* to providers:

```yaml
projects:
  - id: "customer-chat-prod"
    provider: "openai_default"
    api_keys:
      - "proj-chat-key-123"
      - "proj-chat-key-456"
```

Your applications use `proj-chat-key-123` as their API key when calling Straja.

---

## 🔐 Key Model

### Application key (per project)

- Example: `"proj-chat-key-123"`  
- Sent by your apps: `Authorization: Bearer proj-chat-key-123`  
- Selects a project → provider → policy config

### Provider key (private inside Straja)

- Example: `OPENAI_API_KEY=sk-...`  
- Only exists in env / secret store  
- Used by Straja for upstream API calls  
- Never returned to or visible by applications

---

## 🔄 Request Flow

```text
Application
  → Authorization: Bearer <project_key>
  → Straja Gateway
    → Policy check (before model)
    → Provider routing (e.g. openai_default)
    → Upstream LLM (OpenAI)
    ← Straja
      → Policy check (after model)
      → Activation event (JSON)
    ← Application (OpenAI-compatible response)
```

The HTTP surface is intentionally OpenAI-shaped (`/v1/chat/completions`, `model`, `messages`, etc.).

---

## 🛡️ Policies (before/after model)

Straja runs heuristics in two stages via the policy engine.

### BeforeModel (request side)

Runs on the last user message, with separate categories:

- **Banned words** – simple blocklist (configurable via `policy.banned_words_list`)  
- **PII / secrets** – regex heuristics for:  
  - emails  
  - phone numbers  
  - credit cards  
  - IBANs  
  - long tokens / API keys  
- **Injection** – SQL / command-injection-like patterns  
- **Prompt injection** – phrases like “ignore previous instructions”, “forget all previous instructions”  
- **Jailbreak** – “do anything now”, “no restrictions”, etc.  
- **Toxicity** – simple abusive language patterns  

Each category can be configured with an action:

- `"block"` – reject the request before the model  
- `"log"` – allow but log the hit  
- `"ignore"` – do nothing  
- `"redact"` – mutate the prompt (e.g. replace PII with `[REDACTED_EMAIL]`) and continue  

Multiple categories can fire at once. Straja:

- Collects all categories in `policy_hits`  
- Redacts in-place where the action is `"redact"` (PII, injection, etc.)  
- Blocks if **any** blocking category fires

### AfterModel (response side)

Runs on the model output:

- Redacts obvious secrets/PII in the completion body using a conservative regex  
- Marks the request with an `output_redaction` policy hit when something was actually redacted  

Defaults are conservative: many safety checks are enabled and blocking, toxicity is `log` by default.

---

## 🔥 Activation Events

Straja builds one canonical activation event per request and reuses it for logs, the `X-Straja-Activation` response header, and optional delivery sinks. The request path never blocks: events are enqueued to a bounded worker queue (default 1000; drops when full, with counters).

Canonical payload (fields are redacted as needed):

```json
{
  "timestamp": "2025-11-22T19:47:47.321304Z",
  "request_id": "b82f0c0f2f8d4c6e8c45da54e2121e3a",
  "project_id": "default",
  "provider_id": "openai_default",
  "model": "gpt-4.1-mini",
  "decision": "allow",
  "policy_hits": [
    {"category": "pii", "action": "redact", "score": 0.82}
  ],
  "policy_hit_categories": ["pii"],
  "prompt_preview": "please use [REDACTED_EMAIL] in a sentence",
  "completion_preview": "Sure! Here's a sentence using [REDACTED_EMAIL]...",
  "safety_scores": {"pii_email": 0.82},
  "safety_thresholds": {"pii.warn": 0.5},
  "latencies_ms": {"pre_policy": 2.1, "provider": 48.0}
}
```

Key fields:

- `decision` – `allow`, `blocked_before_policy`, `blocked_after_policy`, or `error_provider`  
- `policy_hits` – per-category decision/action (+ optional score/reason); `policy_hit_categories` keeps the legacy string list  
- `prompt_preview` / `completion_preview` – respect `logging.activation_level` (`metadata` | `redacted` | `full`)  
- Optional maps include safety scores/thresholds and latency timings when available.

### Configuring sinks (non-blocking)

Add an `activation` block to `straja.yaml`:

```yaml
activation:
  enabled: true                # keep false to stay header+log only
  queue_size: 1000             # drop when full
  workers: 1
  shutdown_timeout: "2s"       # drain best-effort on shutdown
  sinks:
    - type: "file_jsonl"
      path: "./tmp/activation/events.jsonl"
    - type: "webhook"
      url: "http://127.0.0.1:8099/activation"
      timeout: "2s"
      headers:
        X-Auth: "dev-token"
```

Supported sinks:

- `file_jsonl` – appends one JSON event per line; creates parent dirs; flushes each line; single-writer to avoid corruption.
- `webhook` – POST `application/json` with 2 retries (100ms, 300ms backoff); treats non-2xx as failure with a logged status/body snippet; per-request timeout defaults to 2s.

Counters tracked internally:

- `activation_enqueued_total`
- `activation_dropped_total`
- `activation_sink_success_total{sink}`
- `activation_sink_failure_total{sink}`

### Local webhook receiver

For quick testing, run the dev receiver:

```bash
make activation-receiver           # starts on :8099
```

Point a webhook sink at `http://127.0.0.1:8099/activation` and watch events printed to stdout.

---

## 💻 Using Straja from SDKs

Example with the official OpenAI Node SDK, pointing it at Straja instead of OpenAI directly:

```ts
import OpenAI from "openai";

const client = new OpenAI({
  apiKey: "local-dev-key-123",           // project key from straja.yaml
  baseURL: "http://localhost:8080/v1",   // Straja instead of api.openai.com
});

const res = await client.chat.completions.create({
  model: "gpt-4.1-mini",
  messages: [{ role: "user", content: "Hello" }],
});
```

Because Straja returns an OpenAI-compatible JSON shape, your existing client code should “just work”.

---

## 🧭 Straja Console (built-in UI)

When the gateway is running, a lightweight console UI is served at:

```text
/console
```

Features:

- Select project (based on your `straja.yaml` config)  
- Send test prompts from the browser  
- View the raw OpenAI-compatible response  
- Inspect the activation event from the `X-Straja-Activation` header  
- See the final decision (`allow`, `blocked_before_policy`, etc.) as a status badge  

This console is meant as a local debugging and exploration tool, not a production dashboard.

---

## 🧱 Directory Structure

```text
straja/
  cmd/straja/        → CLI entrypoint
  internal/
    server/          → HTTP server and routing
    provider/        → Upstream providers (e.g. OpenAI)
    policy/          → Policy engine (heuristics, actions)
    inference/       → Internal normalized request/response model
    auth/            → Project ↔ API key mapping
    config/          → YAML config loader + defaults
    activation/      → Activation event emitter(s)
```

---

## 🧪 Local Testing & Development

Common commands:

```bash
# Run all tests
make test

# Basic lint (go vet)
make lint

# Format Go files
make fmt

# Tidy Go modules
make tidy

# Build binary
make build
```

If you change configuration or policy logic, add/update tests in `internal/policy` and keep `make test` green.

---

## ⚡️ StrajaGuard Performance Tuning

- **STRAJA_GUARD_MAX_SESSIONS** – caps concurrent StrajaGuard inference sessions (pool size). More sessions increase concurrency but also CPU/memory contention; too many can hurt p95 latency.
- **STRAJA_GUARD_INTRA_THREADS** – CPU threads a single inference can use. Higher can reduce single-request latency but reduces how many requests run smoothly in parallel.
- **STRAJA_GUARD_INTER_THREADS** – inter-op parallelism inside ONNX Runtime. For low-latency, small-batch inference, keep at 1 for stability.
- **Defaults (balanced start):** `MAX_SESSIONS=2`, `INTRA_THREADS=4`, `INTER_THREADS=1`.
- **How to tune:** start with defaults → run `make loadtest-mock` to isolate gateway + StrajaGuard → increase `MAX_SESSIONS` slowly until throughput stops improving or p95 worsens → if single-request latency is high, raise `INTRA_THREADS` (expect more contention) → keep `INTER_THREADS=1` unless you have measured reason to change → tune against p95/dropped iterations, not just averages.
- **Example profiles:** small box (2–4 cores): `MAX_SESSIONS=1–2`, `INTRA_THREADS=2–4`, `INTER_THREADS=1`; mid box (8 cores): `MAX_SESSIONS=2–4`, `INTRA_THREADS=4`, `INTER_THREADS=1`; big box (16–32 cores): `MAX_SESSIONS=4–8`, `INTRA_THREADS=4–8`, `INTER_THREADS=1`. Measure and adjust; if p95 rises, reduce `MAX_SESSIONS` or `INTRA_THREADS`.
- **Warning:** higher isn’t always better; over-tuning can increase contention and worsen latency under load. Always measure with realistic traffic.

---

## 📈 Load Testing

- Prerequisites: run the gateway locally with a valid `straja.yaml` and API key; enable StrajaGuard ML + bundle for ML runs or set `STRAJA_ALLOW_REGEX_ONLY=true` to force regex-only.
- Install k6 (e.g., `brew install k6`) and ensure `$PATH` can find it.
- Run `make loadtest` (uses `tools/loadtest/chat_completion.js`, defaults: `STRAJA_BASE_URL=http://localhost:8080`, `STRAJA_QPS=20`, `STRAJA_DURATION=60s`, `STRAJA_CONCURRENCY=10`); adjust env vars as needed.
- `make loadtest-ml` reminds you to keep ML enabled; `make loadtest-regex` reminds you to disable ML for comparison.
- `make loadtest-mock` starts Straja with `examples/straja.mock.yaml` (mock upstream) and runs k6 so you can measure Straja overhead without OpenAI latency; logs go to `/tmp/straja_mock_gateway.log` (set `STRAJA_API_KEY=mock-api-key` for the mock project). Mock latency is configurable via `MOCK_DELAY_MS` (default 50ms).
- `make loadtest-mock-delay` runs the mock server with a 50ms artificial delay if you want to emulate upstream latency while keeping responses local.
- Interpret the k6 summary (req/s, latency percentiles, error rate). Compare regex-only vs ML-enabled runs, and mock vs real upstream, to understand the overhead of local inference and provider latency.  

---

## 📝 License

MIT

---

## 💬 Contact

- Email: **hello@straja.ai**  
- Website: **https://straja.ai**
