# OpenAI API Integration

Source of truth: `internal/server/server.go`, `internal/server/responses_handler.go`, `internal/provider/openai.go`, `internal/config/*`.

This page describes how Straja integrates with OpenAI-compatible clients and OpenAI-compatible upstream providers.

## Supported API surface

Straja exposes two OpenAI-compatible endpoints:

- `POST /v1/chat/completions`
- `POST /v1/responses`

These routes are intended for projects bound to `openai` (or `mock`) providers.

## Auth model

Client auth to Straja project keys:

- Standard OpenAI style: `Authorization: Bearer <PROJECT_API_KEY>`
- Also accepted: `x-api-key: <PROJECT_API_KEY>`

Straja then injects upstream provider credentials from config (`providers.<name>.api_key_env` / `api_key`).

## Provider config

Example provider + project:

```yaml
default_provider: "openai_demo"

providers:
  openai_demo:
    type: "openai"
    base_url: "https://api.openai.com/v1"   # optional; this is the default
    api_key_env: "OPENAI_API_KEY"
    allowed_models:
      - "gpt-4.1-mini"

projects:
  - id: "demo-openai"
    provider: "openai_demo"
    api_keys:
      - "local-dev-key-openai-123"
```

## Chat Completions integration details

Route:

- `POST /v1/chat/completions`

Supported payload features:

- `model`
- `messages`
- `tools`
- `tool_choice`
- `stream`

### Tool calls

Straja supports tool-call flows end-to-end in chat completions:

- Request-side tool definitions (`tools`) and `tool_choice` are forwarded upstream.
- Assistant `tool_calls` in upstream responses are returned to clients.
- `finish_reason: "tool_calls"` is preserved.
- Streamed tool-call arguments (`choices[].delta.tool_calls[].function.arguments`) are included in post-check analysis.

### Request hardening / policy

Pre-model policy checks operate on normalized message text and include:

- message text content
- tool call argument strings in `messages[].tool_calls[].function.arguments`

If blocked by policy, Straja returns `403` with OpenAI-style error.

### Response checks

Post-model response guard considers both:

- assistant text
- tool call arguments returned by the model

## Responses API integration details

Route:

- `POST /v1/responses`

Behavior:

- Request is proxied upstream with Straja pre-check hardening.
- Non-stream response may be redacted before returning.
- Stream response is passthrough; post-check result is available after completion via request status.

### Tool/function call coverage

For Responses API output, Straja post-check scanning includes:

- `output[].content[].text`
- `output[].type == "function_call"` with `arguments`
- structured tool input payloads (`tool_use` / `tool_call` `input` string leaves)
- stream deltas for function-call args (`response.function_call_arguments.delta`)

## Streaming behavior

Streaming is passthrough for both endpoints:

- no chunk rewriting in-flight
- `X-Straja-Request-Id` is returned
- final post-check state is available from:
  - `GET /v1/straja/requests/<request_id>`

For chat completions, streamed text and streamed tool-call arguments are both included in post-check aggregation.

If redaction would be needed during stream mode, activation reports:

- `summary.response_final = warn`
- `summary.response_note = redaction_suggested`

## End-to-end examples

Chat Completions:

```bash
curl -s http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer <PROJECT_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "model":"gpt-4.1-mini",
    "messages":[{"role":"user","content":"Hello"}]
  }'
```

Chat Completions with tools:

```bash
curl -s http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer <PROJECT_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "model":"gpt-4.1-mini",
    "messages":[{"role":"user","content":"Weather in Berlin?"}],
    "tools":[
      {
        "type":"function",
        "function":{
          "name":"get_weather",
          "parameters":{"type":"object","properties":{"city":{"type":"string"}}}
        }
      }
    ],
    "tool_choice":{"type":"function","function":{"name":"get_weather"}}
  }'
```

Responses:

```bash
curl -s http://localhost:8080/v1/responses \
  -H "Authorization: Bearer <PROJECT_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "model":"gpt-4.1-mini",
    "input":"Say hello"
  }'
```

## Error behavior summary

- `401 authentication_error`: missing/invalid project key
- `400 invalid_request_error`: bad input, model not allowed
- `403 policy_error` or `straja_policy_violation`: blocked by policy
- `502 provider_error` / `api_error`: upstream transport/provider failure
- Upstream OpenAI `4xx/5xx` on proxied routes are passed through

## Integration test coverage

OpenAI mocked integration tests:

- `internal/server/chat_tools_test.go`
  - tools + tool_choice normalization
  - assistant tool_calls response mapping
  - `finish_reason=tool_calls` propagation
- `internal/server/chat_stream_test.go`
  - stream passthrough for `/v1/chat/completions`
  - streamed tool-call arguments contribute to post-check outcomes
- `internal/provider/openai_test.go`
  - upstream `/chat/completions` mapping for tools/tool_choice
  - tool_calls parsing from upstream response
- `internal/server/responses_handler_test.go`
  - non-stream function-call argument redaction
  - stream function-call-arguments post-check (`redaction_suggested`)
