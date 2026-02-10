# Activation events and sinks

Sources: `internal/activation/*`, `internal/server/server.go`, `internal/server/request_status.go`

Straja emits one activation event per request. Events are:

- Logged to stdout (redacted)
- Returned in `X-Straja-Activation` response header
- Available via request status lookup using `X-Straja-Request-Id`
- Optionally delivered to sinks asynchronously

## Event shape (Activation v2)

Defined in `internal/activation/activation.go`:

```json
{
  "version": "2",
  "timestamp": "2026-01-30T14:23:46.146298Z",
  "request_id": "req_123",

  "meta": {
    "project_id": "default",
    "provider_id": "openai_default",
    "provider": "openai_default",
    "model": "gpt-4.1-mini",
    "mode": "non_stream"
  },

  "summary": {
    "request_final": "redact",
    "response_final": "allow",
    "response_note": "redaction_suggested",
    "blocked": false,
    "categories": ["secrets", "pii"]
  },

  "request": {
    "decision": {
      "final": "redact",
      "reason_categories": ["secrets"],
      "actions": [
        {
          "category": "secrets",
          "action": "redact",
          "confidence": 1.0,
          "sources": ["regex"]
        }
      ]
    },
    "preview": {
      "prompt": "string"
    },
    "hits": [
      {
        "category": "secrets",
        "action": "redact",
        "confidence": 1.0,
        "sources": ["regex"]
      }
    ],
    "scores": {
      "contains_personal_data": 0.47,
      "contains_secrets_maybe": 0.47,
      "data_exfil_attempt": 0.47,
      "jailbreak": 0.48,
      "prompt_injection": 0.48
    },
    "latency_ms": 57.07
  },

  "response": {
    "decision": {
      "final": "allow",
      "note": "redaction_suggested",
      "reason_categories": ["pii"],
      "actions": [
        {
          "category": "pii",
          "action": "redact",
          "confidence": 1.0,
          "sources": ["regex"]
        }
      ]
    },
    "preview": {
      "output": "string"
    },
    "hits": [
      {
        "category": "pii",
        "action": "redact",
        "confidence": 1.0,
        "sources": ["regex"]
      }
    ],
    "scores": {
      "contains_personal_data": 0.46,
      "contains_secrets_maybe": 0.48,
      "data_exfil_attempt": 0.47,
      "jailbreak": 0.48,
      "prompt_injection": 0.49
    },
    "latency_ms": 58.13
  },

  "intel": {
    "status": "online_validated",
    "bundle_version": "0.1.0",
    "last_validated_at": "2026-01-30T14:22:51Z",
    "cache_present": true,
    "strajaguard": {
      "status": "online_validated",
      "bundle_version": "20251213-215605",
      "model": "strajaguard_v1"
    },
    "thresholds": {
      "prompt_injection": { "warn": 0.6, "block": 0.8 },
      "jailbreak": { "warn": 0.6, "block": 0.8 },
      "data_exfil": { "warn": 0.55, "block": 0.75 },
      "secrets": { "warn": 0.5, "block": 0.85 },
      "pii": { "warn": 0.5 }
    }
  },

  "timing_ms": {
    "provider": 1230.61,
    "total": 1345.81
  }
}
```

Key notes:

- `summary.request_final` and `request.decision.final` are one of `allow`, `redact`, `block`.
- `summary.response_final` and `response.decision.final` are one of `allow`, `redact`, `block`.
- `response.decision.note` / `summary.response_note` are `redaction_applied`, `redaction_suggested`, `skipped`, `unsafe_instruction_detected`, `unsafe_instruction_blocked`, or `null`.
- `meta.mode` is `stream` or `non_stream`. In streaming mode, Straja never mutates the response; if post-check would have redacted in non-stream mode, `response.decision.note` is `redaction_suggested` and `response.decision.final` remains `allow`. Response guard matches also keep `response.decision.final` as `allow` and set `response.decision.note` to `unsafe_instruction_detected`.
- Post-LLM checks never block responses; `response.decision.final` is `allow` or `redact` in normal operation.
- `request.preview.prompt` and `response.preview.output` are controlled by `logging.activation_level` and are always redacted previews.
- `request.hits` and `response.hits` may include `evidence` snippets (redacted) when heuristics match.
- ML scores appear only in `request.scores` and `response.scores`. Thresholds appear only in `intel.thresholds`.
- When `intel.strajaguard.family: strajaguard_v1_specialists` is enabled, `intel.strajaguard.model` is `strajaguard_v1_specialists` and ML scores include `prompt_injection`, `jailbreak`, and `contains_personal_data`.
- When specialists are enabled, `intel.strajaguard.specialists_config_source` is `"embedded"` or `"file"` (config override).
- Specialists hits carry sources: `ml:straja/prompt_injection`, `ml:straja/jailbreak`, and `ner:straja/pii_ner`.
- When specialists ensembles are enabled, additive transparency fields are included under `request.strajaguard` for:
  - `request.strajaguard.prompt_injection` (`ensemble` + per-detector `detectors`)
  - `request.strajaguard.jailbreak` (`ensemble` + per-detector `detectors`)

## Request status API

For streaming responses, post-check results are retrieved via:

```
GET /v1/straja/requests/{request_id}
```

Response:

```json
{
  "status": "pending",
  "activation": null
}
```

```json
{
  "status": "completed",
  "activation": { "...": "activation event payload" }
}
```

The `request_id` is provided in `X-Straja-Request-Id` on inference responses.

## Sinks

Configure sinks under `activation.sinks` (see `configuration.md`).

### `file_jsonl`

- Appends one JSON event per line.
- Creates parent directories if missing.
- Flushes after each write.

### `webhook`

- POSTs `application/json` to the configured URL.
- Per-request timeout defaults to `2s`.
- Retries twice with backoff (100ms, 300ms) on errors or non-2xx responses.

### `telegram`

Source: `internal/activation/sink_telegram.go`, `internal/server/server.go`, `internal/config/config.go`

- Sends a short, redacted alert message via Telegram Bot API `sendMessage`.
- Always uses redacted summary fields (no raw prompt/response/tool args).
- Supports per-sink rate limiting and a max message length cap.

Required config keys:

- `token_env` (env var name that stores the bot token)
- `chat_id_env` (env var name that stores the chat id)

Example:

```yaml
activation:
  enabled: true
  sinks:
    - type: telegram
      token_env: TELEGRAM_BOT_TOKEN
      chat_id_env: TELEGRAM_CHAT_ID
      api_base_url: "https://api.telegram.org"
      disable_web_page_preview: true
      parse_mode: "MarkdownV2"
      timeout: "2s"
      rate_limit_per_sec: 1
      min_level: "warn"
      only_categories: ["toolgate", "prompt_injection", "jailbreak", "pii", "data_exfil"]
      send_on_actions: ["block", "warn"]
      max_message_len: 3500
```

Operational notes:

- Create a bot with BotFather to get a token.
- Send a message to the bot, then use `getUpdates` to find the chat id.
- If `parse_mode: MarkdownV2` is set, the message is escaped before sending.

### OpenTelemetry (OTLP)

OpenTelemetry is **not** an activation sink. It exports telemetry (traces + metrics) about request handling, while activation events are delivered via `X-Straja-Activation` and optional sinks above.

To enable OTLP export:

```yaml
telemetry:
  enabled: true
  endpoint: http://localhost:4317
  protocol: grpc
```

You can override the endpoint/protocol via environment variables:

- `OTEL_EXPORTER_OTLP_ENDPOINT` (overrides `telemetry.endpoint`)
- `OTEL_EXPORTER_OTLP_PROTOCOL` (overrides `telemetry.protocol`, expects `grpc` or `http`)

Source: `internal/telemetry/telemetry.go`, `internal/server/server.go`, `docs/configuration.md`, `docs/environment-variables.md`.

## Delivery model

Sinks are delivered asynchronously via a bounded in-memory queue (`queue_size`) and a worker pool (`workers`). If the queue is full or the emitter is closed, events are dropped and the request path is not blocked.
