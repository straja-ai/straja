# Moltbot + Codex (Responses API) via Straja

Straja exposes the OpenAI Responses API at `/v1/responses` and applies pre-LLM hardening (prompt-injection/jailbreak detection and PII/secrets redaction/blocking) on the incoming request only. Streaming responses are passed through byte-for-byte with no post-LLM inspection or modification.

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

## Moltbot provider config (baseUrl -> Straja)

```yaml
provider:
  type: openai
  baseUrl: http://localhost:8080/v1
  apiKey: ${STRAJA_KEY}
```

## Limitation

Response streaming is not inspected yet; use OS sandboxing / least privilege for tools.
