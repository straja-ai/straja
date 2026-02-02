# Security considerations

Sources: `internal/config/validate.go`, `internal/server/server.go`, `internal/redact/redact.go`

## Provider URL SSRF protection

- Provider `base_url` must be `http` or `https`.
- Private/loopback hosts are blocked unless `allow_private_networks: true`.

This check is enforced in `internal/config/validate.go`.

## Request hardening

Configured in `server.*`:

- `max_request_body_bytes`
- `max_messages`
- `max_total_message_chars`
- `max_in_flight_requests`
- `rate_limit_per_ip` / `rate_limit_per_ip_burst`

These limits reject oversized requests or high concurrency before hitting upstream providers.

Per-IP rate limit settings (from `server` config):

- `rate_limit_per_ip` (int, default `0` = disabled)
- `rate_limit_per_ip_burst` (int, default `0` = defaults to `rate_limit_per_ip` when enabled)

Per-IP rate limiting uses `X-Forwarded-For` or `X-Real-IP` when present; otherwise it falls back to the TCP remote address. Only trust proxy headers when the gateway is behind a trusted reverse proxy.

## Model allowlists

Use `projects[].allowed_models` and/or `providers[].allowed_models` to restrict which models can be proxied. Project allowlists take precedence over provider allowlists.

## Activation redaction

Activation events and logs are redacted by the redaction utilities in `internal/redact/redact.go`. Logging detail is controlled by `logging.activation_level`:

- `metadata`: no previews
- `redacted`: redacted previews
- `full`: full previews (still pass through redaction)

## Output redaction

After-model output redaction is performed by the policy engine when the intel bundle flags `output_redaction` (`internal/policy/policy.go`, `internal/intel/regex_bundle.go`). This can redact sensitive tokens in model outputs.

## Console exposure

The built-in console (`/console`) does not require authentication and accepts a `project_id` in the body. Expose it only on trusted networks.
