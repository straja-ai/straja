# OpenClaw + OpenAI (Chat + Codex) via Straja

This setup routes OpenClaw’s OpenAI traffic through Straja so you get:

- pre-LLM hardening on requests (PII, secrets, prompt-injection, jailbreak)
- post-LLM checks on responses (PII redaction + data exfil / unsafe instruction warnings)
- OpenAI-compatible endpoints (Chat Completions and Responses)

## Prereqs

- Straja running locally (or reachable) and configured with an OpenAI provider
- A Straja project API key (the key OpenClaw will use), e.g. `STRAJA_KEY`
- Your provider key set for Straja (e.g. `OPENAI_API_KEY`)

## 1) Classic OpenAI API via Straja (Chat Completions)

Endpoint:

- `POST http://localhost:8080/v1/chat/completions`

Quick test:

```bash
curl -s http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $STRAJA_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4.1-mini",
    "messages": [{"role": "user", "content": "Hello from OpenClaw via Straja"}]
  }'
```

## 2) Codex / Responses API via Straja

Endpoint:

- `POST http://localhost:8080/v1/responses`

Non-stream test:

```bash
curl -s http://localhost:8080/v1/responses \
  -H "Authorization: Bearer $STRAJA_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.2-codex",
    "input": "Say hello",
    "stream": false
  }'
```

Streaming test:

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

### Streaming + post-check results (important)

For streaming, Straja passes the upstream stream through without modifying chunks mid-stream. Post-check results are available after completion via the request status API. The streaming response includes `X-Straja-Request-Id`:

```bash
curl -s -H "Authorization: Bearer $STRAJA_KEY" \
  http://localhost:8080/v1/straja/requests/<request_id>
```

Look at:

- `summary.request_final` (request stage)
- `summary.response_final` (response stage)
- `summary.response_note` (for streaming, may indicate `redaction_suggested` or `unsafe_instruction_detected`)

## 3) OpenClaw config (point OpenAI base URL at Straja)

Set OpenClaw’s OpenAI base URL to Straja and use your Straja project key as the API key.

```yaml
provider:
  type: openai
  baseUrl: http://localhost:8080/v1
  apiKey: ${STRAJA_KEY}
```

## What Straja enforces by default

- Request (pre-LLM): prompt-injection + jailbreak + PII
- Can block or redact before the provider is called
- Response (post-LLM): data exfil / unsafe instructions + PII
- Never blocks responses
- May redact non-stream responses
- For streaming: reports `redaction_suggested` instead of modifying the stream

## Limitation (tool execution)

Straja hardens LLM requests and responses. It does not sandbox tools. For OpenClaw/Moltbot tool safety, use OS-level sandboxing and least privilege, and optionally integrate Toolgate checks before tool execution when a hook is available.
