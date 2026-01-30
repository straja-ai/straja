# Troubleshooting

Sources: `internal/server/server.go`, `internal/config/validate.go`, `internal/strajaguard/*`

## Gateway fails to start

- `invalid config: ...`
  - Missing `server.addr`, providers, projects, or default provider.
  - Provider `base_url` invalid or blocked by private network rules.
  - Telemetry enabled without an endpoint.

See validation rules in `internal/config/validate.go`.

## `/readyz` reports not ready

`GET /readyz` returns a JSON payload with `status` and `reason`:

- `config_not_loaded`
- `no_providers_configured`
- `no_projects_configured`
- `strajaguard_ml_inactive` (when `require_ml: true` but ML failed to load)

## 401 Unauthorized from `/v1/chat/completions`

- Missing `Authorization: Bearer <project_key>` header.
- Project key not found in `projects[].api_keys`.

## 400 Bad Request

- Request body too large (exceeds `server.max_request_body_bytes`).
- Too many messages or too many total characters.
- Model not allowed by project/provider allowlist.

## Streaming not working

Streaming is currently not implemented. The gateway accepts the `stream` field but always makes non-streaming upstream calls (`internal/provider/openai.go`).

## 429 Too Many Requests

- `server.max_in_flight_requests` cap exceeded.

## 403 Forbidden (policy)

- `blocked_before_policy`: input blocked by policy.
- `blocked_after_policy`: output blocked after the upstream response.

## StrajaGuard ML not running

Common causes:

- Missing ONNX Runtime shared library (set `ONNXRUNTIME_SHARED_LIBRARY_PATH`).
- Invalid or missing license key.
- Bundle download/verification failure.
- `security.enabled: false` or `intel.strajaguard_v1.enabled: false`.

Check logs for `strajaguard:` status messages and the `intel.strajaguard.status` field in activation events.
