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

Run Straja in a container, mounting your config and injecting the provider key as an env var:

```bash
docker run   -p 8080:8080   -v $(pwd)/straja.yaml:/straja.yaml   -e OPENAI_API_KEY="sk-..."   straja-ai/straja:latest   ./straja --config /straja.yaml
```

Your apps still talk to `http://host:8080/v1` and use **project keys**, not provider keys.

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

For every request Straja emits a structured activation event (currently to stdout and a response header):

Example:

```json
{
  "timestamp": "2025-11-22T19:47:47.321304Z",
  "project_id": "default",
  "provider": "openai_default",
  "model": "gpt-4.1-mini",
  "decision": "allow",
  "prompt_preview": "please use [REDACTED_EMAIL] in a sentence",
  "completion_preview": "Sure! Here's a sentence using "[REDACTED_EMAIL]"...",
  "policy_hits": ["pii"]
}
```

Key fields:

- `decision` – `allow`, `blocked_before_policy`, `blocked_after_policy`, or `error_provider`  
- `policy_hits` – categories that fired (`pii`, `injection`, `prompt_injection`, `jailbreak`, `toxicity`, `output_redaction`, `banned_words`)  
- `prompt_preview` / `completion_preview` – respect `logging.activation_level`  
  - `"metadata"` – short previews  
  - `"redacted"` – PII masked in previews  
  - `"full"` – full prompt/response (for internal use only)

The activation event is also exposed in the **`X-Straja-Activation`** response header as a JSON string.

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

## 🗺 Future Roadmap (High-Level)

Planned directions (subject to change):

- Multiple upstream providers per project (smart routing)  
- Streaming support for chat completions  
- Local ONNX / WebGPU inference backends  
- Richer classifiers (ML-based PII, prompt injection, jailbreaks)  
- Signed intelligence bundles, versioned and updatable  
- More activation sinks (file, webhook, Kafka, OTEL)  
- Web console evolution into a proper activation dashboard  
- License-key validation and telemetry-aware distribution  

---

## 📝 License

MIT

---

## 💬 Contact

- Email: **hello@straja.ai**  
- Website: **https://straja.ai**
