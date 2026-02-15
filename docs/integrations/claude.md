# Claude API Integration

Source of truth: `internal/server/claude_messages_handler.go`, `internal/server/server.go`, `internal/config/*`.

This page describes how Straja integrates with Claude-compatible clients and Claude upstream providers.

## Supported API surface

Straja exposes a Claude-compatible Messages endpoint:

- `POST /v1/messages`

Straja requires the selected project provider to be `type: "claude"` for this route.

If a project is bound to a non-Claude provider, `/v1/messages` returns `400 invalid_request_error`.

## Auth model

Client auth to Straja project keys:

- Preferred for Claude clients: `x-api-key: <PROJECT_API_KEY>`
- Also accepted: `Authorization: Bearer <PROJECT_API_KEY>`

Straja then injects upstream provider credentials from config (`providers.<name>.api_key_env` / `api_key`), so client apps never need upstream Claude keys.

## Provider config

Example provider + project:

```yaml
default_provider: "claude_demo"

providers:
  claude_demo:
    type: "claude"
    base_url: "https://api.anthropic.com/v1"   # optional; this is the default
    api_key_env: "CLAUDE_API_KEY"
    allowed_models:
      - "claude-3-5-sonnet-latest"

projects:
  - id: "demo-claude"
    provider: "claude_demo"
    api_keys:
      - "local-dev-key-claude-123"
```

## Request handling details

Input expectations on `/v1/messages`:

- `model` is required
- `max_tokens` defaults to `1024` if omitted
- `stream` optional
- `messages` required

Pre-model policy hardening scans and enforces policy on:

- message text content
- `system` text
- nested string leaves inside structured content blocks
- nested string leaves inside `tool_use.input` JSON

If blocked by policy, Straja returns:

- HTTP `403`
- Claude-style error envelope (`type: "error"`, `error.type: "invalid_request_error"`)

## Upstream forwarding behavior

Straja forwards to:

- `<provider_base_url>/messages`

Headers to upstream:

- `x-api-key`: provider key from Straja config (not client key)
- `anthropic-version`: client-provided value if present, otherwise default `2023-06-01`
- `anthropic-beta`: forwarded if client sends it

Straja strips client auth headers before forwarding.

## Response handling (non-stream)

For non-stream responses, Straja:

1. Receives upstream JSON
2. Runs post-check/redaction
3. Returns Claude-compatible JSON body

Post-check applies to:

- text output blocks (`content[].text`)
- nested string leaves in assistant `tool_use.input` blocks

If redaction occurs, response is returned with redacted content and activation reflects `summary.response_final = redact`.

## Response handling (stream)

For stream responses, Straja does SSE passthrough (no in-flight chunk rewriting).

After stream completion, Straja performs post-check using captured output from:

- text deltas
- `input_json_delta.partial_json` fragments for tool-use blocks

If redaction would be needed in stream mode, activation reports:

- `summary.response_final = warn`
- `summary.response_note = redaction_suggested`

## Request status and activation

All `/v1/messages` responses include:

- `X-Straja-Request-Id`

Fetch final activation/post-check result:

```bash
curl -s -H "x-api-key: <PROJECT_API_KEY>" \
  http://localhost:8080/v1/straja/requests/<request_id>
```

## End-to-end examples

Non-stream:

```bash
curl -s http://localhost:8080/v1/messages \
  -H "x-api-key: <PROJECT_API_KEY>" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-3-5-sonnet-latest",
    "max_tokens": 256,
    "messages": [
      {"role": "user", "content": "Hello from Straja"}
    ]
  }'
```

Stream:

```bash
curl -N http://localhost:8080/v1/messages \
  -H "x-api-key: <PROJECT_API_KEY>" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-3-5-sonnet-latest",
    "max_tokens": 256,
    "messages": [
      {"role": "user", "content": "Stream hello"}
    ],
    "stream": true
  }'
```

## Error behavior summary

- `401 authentication_error`: missing/invalid project key
- `400 invalid_request_error`: bad input, model not allowed, provider mismatch
- `403 invalid_request_error`: blocked by policy before provider
- `502 api_error`: upstream transport/provider failure
- Upstream Claude `4xx/5xx`: status and body are passed through

## Integration test coverage

Mocked Claude integration tests:

- `internal/server/claude_messages_handler_test.go`
  - non-stream passthrough
  - stream passthrough
  - provider mismatch rejection
  - pre-policy block
  - pre-LLM redaction in tool input
  - post-check redaction in tool-use response blocks
  - stream post-check behavior for tool `input_json_delta`
- `internal/provider/claude_test.go`
  - upstream path/header/payload mapping and usage mapping
