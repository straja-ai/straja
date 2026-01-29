# Activation events and sinks

Sources: `internal/activation/*`, `internal/server/server.go`

Straja emits one activation event per request. Events are:

- Logged to stdout (redacted)
- Returned in `X-Straja-Activation` response header
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
  "safety_scores": {},
  "safety_thresholds": {},
  "latencies_ms": {"pre_policy": 1.2, "provider": 30.5}
}
```

Key notes:

- `decision` values are defined in `internal/activation/activation.go`: `allow`, `blocked_before_policy`, `blocked_after_policy`, `error_provider`.
- `prompt_preview` / `completion_preview` are controlled by `logging.activation_level`.
- `policy_decisions`, `safety_scores`, and `safety_thresholds` are present when the security layer runs.

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
