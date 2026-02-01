# Moltbot + Codex (Responses API) via Straja

Straja exposes the OpenAI Responses API at `/v1/responses` and applies pre-LLM hardening (prompt-injection/jailbreak detection and PII/secrets redaction/blocking). Post-LLM checks run for both non-streaming and streaming responses; in streaming mode, output is not modified mid-stream and any redaction or response-guard findings are reported after completion via `response_note` in the activation summary. Responses are never blocked by post-checks. Streaming responses are passed through byte-for-byte and never include custom SSE events; post-check results are retrieved via the request status API using `X-Straja-Request-Id`. Source: `internal/server/responses_handler.go`, `internal/server/post_check.go`, `internal/server/request_status.go`.

## Streaming example (curl)

```bash
curl -N http://localhost:8080/v1/responses \
  -H "Authorization: Bearer $STRAJA_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.2-codex",
    "input": "Stream hello",
    "stream": true
  }'
```

The response includes `X-Straja-Request-Id`. Use it to fetch post-check results once the stream ends:

```bash
curl -H "Authorization: Bearer $STRAJA_KEY" \
  http://localhost:8080/v1/straja/requests/<request_id>
```

Activation responses now include a `summary` object with `request_final`, `response_final`, and `response_note` (for streaming, `response_note` may be `redaction_suggested` or `unsafe_instruction_detected`).

## Moltbot provider config (baseUrl -> Straja)

```yaml
provider:
  type: openai
  baseUrl: http://localhost:8080/v1
  apiKey: ${STRAJA_KEY}
```

## Limitation

Response streaming is not modified; post-check results are fetched via `GET /v1/straja/requests/{request_id}` after the stream completes. Use OS sandboxing / least privilege for tools. Source: `internal/server/request_status.go`, `internal/activation/activation.go`.
