# Activation events and sinks

Sources: `internal/activation/*`, `internal/server/server.go`, `internal/server/request_status.go`

Straja emits one activation event per request. Events are:

- Logged to stdout (redacted)
- Returned in `X-Straja-Activation` response header
- Available via request status lookup using `X-Straja-Request-Id`
- Optionally delivered to sinks asynchronously

## Event shape

Defined in `internal/activation/activation.go`:

```json
{
  "timestamp": "2025-01-01T00:00:00Z",
  "request_id": "...",
  "project_id": "default",
  "provider_id": "openai_default",
  "model": "gpt-4.1-mini",
  "decision": "allow",
  "policy_hits": [{"category":"pii","action":"redact"}],
  "policy_hit_categories": ["pii"],
  "prompt_preview": "...",
  "completion_preview": "...",
  "intel_status": "online_validated",
  "intel_bundle_version": "...",
  "intel_last_validated_at": "...",
  "intel_cache_present": true,
  "strajaguard_status": "online_validated",
  "strajaguard_bundle_version": "...",
  "strajaguard": {"model":"strajaguard_v1","scores":{},"flags":[]},
  "policy_decisions": [],
  "post_policy_hits": [{"category":"secrets","action":"redact"}],
  "post_policy_decisions": [{"category":"secrets","action":"redact"}],
  "post_decision": "redacted",
  "output_preview": "...",
  "post_check_latency_ms": 8.4,
  "post_safety_scores": {"contains_secrets_maybe": 0.42},
  "post_safety_flags": ["contains_secrets_maybe"],
  "safety_scores": {},
  "safety_thresholds": {},
  "latencies_ms": {"pre_policy": 1.2, "provider": 30.5}
}
```

Key notes:

- `decision` values are defined in `internal/activation/activation.go`: `allow`, `blocked_before_policy`, `blocked_after_policy`, `error_provider`.
- `prompt_preview` / `completion_preview` are controlled by `logging.activation_level`.
- `post_*` fields reflect post-LLM checks on model output and only include redacted previews.
- `post_safety_scores` / `post_safety_flags` capture StrajaGuard output-side scores when available.
- `policy_decisions`, `safety_scores`, and `safety_thresholds` are present when the security layer runs.

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

## Delivery model

Sinks are delivered asynchronously via a bounded in-memory queue (`queue_size`) and a worker pool (`workers`). If the queue is full or the emitter is closed, events are dropped and the request path is not blocked.
