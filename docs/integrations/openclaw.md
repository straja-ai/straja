# OpenClaw + OpenAI / Claude via Straja

This setup routes OpenClaw model traffic through Straja so you get:

- pre-LLM hardening on requests (PII, secrets, prompt-injection, jailbreak)
- post-LLM checks on responses (PII redaction + data exfil / unsafe instruction warnings)
- OpenAI-compatible and Claude-compatible API surfaces

## Prereqs

- Straja running locally (or reachable)
- A Straja project API key from `projects[].api_keys`
- Your upstream provider key configured in Straja:
  - OpenAI example: `OPENAI_API_KEY`
  - Claude example: `CLAUDE_API_KEY` (or whichever env var your provider config uses)

## 1) OpenAI API setup via Straja

### Chat Completions endpoint

- `POST http://localhost:8080/v1/chat/completions`

```bash
curl -s http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer <PROJECT_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4.1-mini",
    "messages": [{"role": "user", "content": "Hello from OpenClaw via Straja"}]
  }'
```

### Responses endpoint

- `POST http://localhost:8080/v1/responses`

```bash
curl -s http://localhost:8080/v1/responses \
  -H "Authorization: Bearer <PROJECT_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4.1-mini",
    "input": "Say hello",
    "stream": false
  }'
```

## 2) Claude API setup via Straja

### Messages endpoint

- `POST http://localhost:8080/v1/messages`

```bash
curl -s http://localhost:8080/v1/messages \
  -H "x-api-key: <PROJECT_API_KEY>" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-3-5-sonnet-latest",
    "max_tokens": 256,
    "messages": [{"role": "user", "content": "Hello from OpenClaw via Straja"}]
  }'
```

Streaming example:

```bash
curl -N http://localhost:8080/v1/messages \
  -H "x-api-key: <PROJECT_API_KEY>" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-3-5-sonnet-latest",
    "max_tokens": 256,
    "messages": [{"role": "user", "content": "Stream hello"}],
    "stream": true
  }'
```

## 3) OpenClaw config examples

OpenAI-style:

```yaml
provider:
  type: openai
  baseUrl: http://localhost:8080/v1
  apiKey: project-api-key-from-straja-config
```

Claude-style:

```yaml
provider:
  type: claude
  baseUrl: http://localhost:8080/v1
  apiKey: project-api-key-from-straja-config
```

## Streaming post-check status

For streaming requests, Straja passes stream chunks through without in-flight modification. Post-check outcomes are available after completion via:

```bash
curl -s -H "Authorization: Bearer <PROJECT_API_KEY>" \
  http://localhost:8080/v1/straja/requests/<request_id>
```

Check:

- `summary.request_final`
- `summary.response_final`
- `summary.response_note`
