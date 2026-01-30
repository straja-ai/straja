# Moltbot + Codex (Responses API) via Straja

Straja exposes the OpenAI Responses API at `/v1/responses` and applies pre-LLM hardening (prompt-injection/jailbreak detection and PII/secrets redaction/blocking). For non-streaming responses, Straja also runs a post-LLM check on output text to redact or block per policy. Streaming responses are passed through byte-for-byte and never include custom SSE events; post-check results are retrieved via the request status API using `X-Straja-Request-Id`. Source: `internal/server/responses_handler.go`, `internal/server/post_check.go`, `internal/server/request_status.go`.

## Streaming example (curl)

```bash
curl -N http://localhost:8080/v1/responses \
  -H "Authorization: Bearer $STRAJA_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "codex-mini",
    "input": "Stream hello",
    "stream": true
  }'
```

The response includes `X-Straja-Request-Id`. Use it to fetch post-check results once the stream ends:

```bash
curl -H "Authorization: Bearer $STRAJA_KEY" \
  http://localhost:8080/v1/straja/requests/<request_id>
```

## Moltbot provider config (baseUrl -> Straja)

```yaml
provider:
  type: openai
  baseUrl: http://localhost:8080/v1
  apiKey: ${STRAJA_KEY}
```

## Limitation

Response streaming is not modified; post-check results are fetched via `GET /v1/straja/requests/{request_id}` after the stream completes. Use OS sandboxing / least privilege for tools. Source: `internal/server/request_status.go`, `internal/activation/activation.go`.
