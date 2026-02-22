# Straja Gateway

Straja Gateway is a local AI security gateway. It sits between your applications and LLM providers (OpenAI, Claude), inspecting every request and response with on-device ML classifiers and regex pattern matching. Nothing leaves your machine for analysis.

Drop-in compatible with the OpenAI and Claude SDKs — change the base URL, use a Straja API key, keep everything else the same.

## Why

When applications talk directly to LLM providers, you have no visibility into what's being sent or returned. Straja Gateway gives you a control point:

- **Prompt injection detection** — ML classifiers (DeBERTa-v3 ensemble) + regex patterns score every user message
- **Jailbreak detection** — Two specialist models vote on attempts to bypass model safety
- **PII detection and redaction** — NER model identifies personal data (emails, phones, credit cards, IBANs); regex catches tokens and secrets. Configurable to redact, block, or log
- **Secrets blocking** — API keys and credentials detected in messages are blocked before they reach the provider
- **Data exfiltration prevention** — Catches curl uploads, scp transfers, and encoded payloads in both prompts and tool calls
- **Tool call safety** — Toolgate inspects shell commands, file reads, and HTTP requests before execution. Blocks destructive operations, privilege escalation, and data exfil
- **Response scanning** — Model outputs are checked for unsafe instructions (destructive commands, exfil patterns) the model may have been tricked into generating
- **Full audit trail** — Every request produces a structured activation event with ML scores, decisions, latency, and redacted previews. Delivered via headers, logs, file, webhook, or Telegram

All ML inference runs locally via ONNX Runtime. The StrajaGuard models are downloaded as signed bundles, verified with Ed25519 signatures, and cached on disk.

## How It Works

```
   Your App (OpenAI/Claude SDK)
              │
              ▼
   ┌─────────────────────┐
   │   Straja Gateway     │
   │                      │
   │  1. Authenticate     │  ← project API key
   │  2. Pre-check        │  ← StrajaGuard ML + regex
   │  3. Proxy to LLM     │  ← OpenAI / Claude / mock
   │  4. Post-check       │  ← PII redaction, response guard
   │  5. Activation event │  ← structured audit log
   │                      │
   └─────────────────────┘
              │
              ▼
   LLM Provider (OpenAI / Anthropic)
```

Your app authenticates with a project-scoped API key. Straja resolves the project, runs pre-model checks (ML classifiers + regex), proxies the request to the configured provider, runs post-model checks on the response, emits an activation event, and returns the result. Provider API keys never leave the gateway.

## Quick Start

```bash
# Install
curl -fsSL https://straja.ai/install.sh | bash

# Configure
export STRAJA_TRUST_KEY="STRAJA-TRUST-..."       # enables signed ML models
export OPENAI_API_KEY="sk-..."                     # or CLAUDE_API_KEY
export STRAJA_CONSOLE_SESSION_SECRET="random-str"  # for the web console

# Run
straja --config straja.yaml
```

Then point your SDK at `http://localhost:8080`:

```python
# OpenAI SDK — no other changes needed
client = OpenAI(base_url="http://localhost:8080/v1", api_key="your-project-key")
```

```python
# Claude SDK
client = Anthropic(base_url="http://localhost:8080/v1", api_key="your-project-key")
```

## StrajaGuard

StrajaGuard is the on-device ML safety layer. Five specialist models run via ONNX Runtime:

| Model | Task |
|-------|------|
| `prompt_injection_deberta_v3` | Prompt injection (sequence classification) |
| `prompt_injection_vijil` | Prompt injection (sequence classification) |
| `jailbreak_jackhhao` | Jailbreak (sequence classification) |
| `jailbreak2xl` | Jailbreak (Qwen next-token binary) |
| `pii_ner` | PII entity recognition (token classification) |

Models are composed into **ensembles** per category. You configure the aggregation method (`any`, `mean`, `median`) and per-category thresholds:

```yaml
security:
  categories:
    prompt_injection:
      warn_threshold: 0.60
      block_threshold: 0.80
      ensemble: any
    jailbreak:
      warn_threshold: 0.60
      block_threshold: 0.80
      ensemble: mean
```

**Bundle integrity**: Models are delivered as signed bundles. Ed25519 signatures are verified at startup. Cached bundles work offline with integrity checks. If a bundle is corrupted or missing, the gateway can be configured to fail hard (`require_ml: true`) or fall back to regex-only.

## Security Categories

Every request is evaluated across these categories. Each has independent thresholds and actions:

| Category | Detection | Default action |
|----------|-----------|----------------|
| Prompt injection | ML ensemble + regex | Block at 0.80 |
| Jailbreak | ML ensemble + regex | Block at 0.80 |
| PII | NER model + regex (email, phone, CC, IBAN, tokens) | Redact |
| Secrets | Regex (API keys, credentials) | Block and redact |
| Data exfiltration | ML + regex (curl uploads, scp, encoded payloads) | Block at 0.75 |
| Banned words | Regex pattern list | Configurable |
| Toxicity | ML score | Log |

Post-model response checks cover PII redaction and **response guard** — scanning model output for unsafe tool instructions (destructive commands, exfil patterns, privilege escalation).

## Toolgate

Toolgate evaluates tool calls before execution. When an agent runtime calls `POST /v1/toolgate/check`, the gateway inspects the tool name and arguments against 25+ compiled rules:

**Shell rules** — Blocks data exfiltration (`curl -F`, `scp`, `rsync`, `netcat`), destructive operations (`rm -rf /`, `dd`, `mkfs`), and privilege escalation (`sudo`, `cron`, `systemd`, profile modification).

**Filesystem rules** — Blocks reads of sensitive paths (`.ssh/id_*`, `.aws/credentials`, `.env`, `/etc/shadow`).

**HTTP rules** — Blocks large POST/PUT bodies to non-allowlisted hosts and base64-encoded payloads.

```yaml
tool_gate:
  enabled: true
  mode: all_tools
  allowlist_commands: ["ls", "cat", "grep"]
  allowlist_hosts: ["api.example.com"]
```

## Activation Events

Every request produces a structured JSON event capturing the complete security picture:

```
version, timestamp, request_id
meta:     project, provider, model
summary:  request_final, response_final, blocked, categories
request:  decision, ML scores, policy hits, latency
response: decision, ML scores, policy hits, latency
intel:    bundle version, StrajaGuard status
timing:   provider_ms, total_ms
```

Events are delivered via:
- `X-Straja-Activation` response header
- `GET /v1/straja/requests/{id}` polling endpoint (for streaming)
- Stdout structured logs
- **Sinks**: `file_jsonl`, `webhook` (with retry), `telegram` (with rate limiting and category filtering)

## Guard API

Use StrajaGuard as a standalone safety service without proxying LLM traffic:

```
POST /v1/guard/request   ← pre-LLM check: returns decision, redactions, ML scores
POST /v1/guard/response  ← post-LLM check: returns decision, redactions
```

For applications that make their own LLM calls but want Straja's safety layer as a hook.

## Projects and Routing

Projects are the unit of access control and routing:

```yaml
providers:
  - name: openai_prod
    type: openai
    api_key_env: OPENAI_API_KEY
    allowed_models: ["gpt-4.1", "gpt-4.1-mini"]

  - name: claude_prod
    type: claude
    api_key_env: CLAUDE_API_KEY

projects:
  - id: backend-team
    provider: openai_prod
    api_keys: ["sk-backend-..."]
    allowed_models: ["gpt-4.1-mini"]

  - id: research-team
    provider: claude_prod
    api_keys: ["sk-research-..."]
```

Each project gets its own API keys and model allowlist. Upstream provider credentials never reach clients. Multiple projects can share a provider with different permissions.

## API Surface

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/chat/completions` | POST | OpenAI Chat Completions proxy |
| `/v1/responses` | POST | OpenAI Responses API proxy |
| `/v1/messages` | POST | Claude Messages API proxy |
| `/v1/guard/request` | POST | Standalone pre-LLM safety check |
| `/v1/guard/response` | POST | Standalone post-LLM safety check |
| `/v1/toolgate/check` | POST | Tool call safety decision |
| `/v1/straja/requests/{id}` | GET | Activation event lookup |
| `/console/` | GET | Built-in web UI |
| `/healthz` | GET | Health probe |
| `/readyz` | GET | Readiness probe |

## Console

Built-in web UI at `/console/` for local debugging. Session-based auth (cookie-signed, 30 min TTL). Displays activation events, ML scores, and decisions in real time. Not intended for production exposure.

## Deployment

### Binary

```bash
curl -fsSL https://straja.ai/install.sh | bash
straja --config straja.yaml
```

### Docker

```bash
docker build -t straja-gateway .
docker run -p 8080:8080 \
  -v ./straja.yaml:/etc/straja/straja.yaml \
  -e STRAJA_TRUST_KEY=... \
  -e OPENAI_API_KEY=... \
  straja-gateway
```

Multi-stage distroless image. ONNX Runtime included. Runs as non-root (UID 65532).

### Request Limits

| Setting | Default |
|---------|---------|
| Max request body | 2 MiB |
| Max messages per request | 64 |
| Max total message chars | 32,000 |
| Max concurrent requests | 200 |
| Per-IP rate limit | Configurable token bucket |

## Observability

- **OpenTelemetry**: OTLP traces and metrics export (gRPC or HTTP). Spans for guard checks, StrajaGuard inference, provider calls.
- **Structured logs**: All output redacted to prevent accidental credential/PII leakage.
- **Activation events**: Per-request timing breakdown, ML scores, decisions, thresholds.

## Documentation

| Topic | Link |
|-------|------|
| Getting started | [docs/getting-started.md](docs/getting-started.md) |
| Installation | [docs/installation.md](docs/installation.md) |
| Configuration | [docs/configuration.md](docs/configuration.md) |
| Environment variables | [docs/environment-variables.md](docs/environment-variables.md) |
| Docker | [docs/docker.md](docs/docker.md) |
| Console | [docs/console.md](docs/console.md) |
| Activation events | [docs/activation.md](docs/activation.md) |
| Telegram sink | [docs/activation-telegram.md](docs/activation-telegram.md) |
| StrajaGuard v1 | [docs/strajaguard-v1.md](docs/strajaguard-v1.md) |
| Toolgate | [docs/toolgate.md](docs/toolgate.md) |
| Guard API | [docs/guard-api.md](docs/guard-api.md) |
| OpenAI integration | [docs/integrations/openai.md](docs/integrations/openai.md) |
| Claude integration | [docs/integrations/claude.md](docs/integrations/claude.md) |
| Security | [docs/security.md](docs/security.md) |

## Related Repositories

| Repo | Purpose |
|------|---------|
| [straja-agent](https://github.com/straja-ai/straja-agent) | Vault-first AI agent runtime |
| [straja-vault](https://github.com/straja-ai/straja-vault) | Document store, search, and execution sandbox |

## License

Apache License, Version 2.0.

## Contact

For questions: **hello@straja.ai**
