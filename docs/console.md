# Built-in console

Source: `internal/console/*`, `internal/server/server.go`, `internal/server/console_stream.go`

The Straja console is served by the gateway at:

- `/console/` (UI)
- `/console/api/projects` (list projects)
- `/console/api/chat` (send a test chat request; supports streaming)

The console is intended for local debugging. It does not require an API key; instead you send a `project_id` in the request body.

## API: list projects

```bash
curl http://localhost:8080/console/api/projects
```

Response:

```json
[{"id":"default","provider":"openai_default"}]
```

## API: chat (non-streaming)

```bash
curl -X POST http://localhost:8080/console/api/chat \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "default",
    "model": "gpt-4.1-mini",
    "messages": [{"role":"user","content":"Hello from console"}]
  }'
```

The response matches the OpenAI-style JSON shape used by `/v1/chat/completions`.

The console also displays activation payloads via the `X-Straja-Activation` response header.

## API: chat (streaming)

Add `"stream": true` to the request body to stream responses via the Responses API. Streaming is pure SSE passthrough (no custom events). The console UI uses `X-Straja-Request-Id` and the request status API to fetch post-check results after the stream completes. It can call the authenticated gateway endpoint (`/v1/straja/requests/{id}`) or the console helper (`/console/api/requests/{id}?project_id=...`). Source: `internal/server/console_stream.go`, `internal/console/static/console.html`, `internal/server/request_status.go`, `internal/server/console_request_status.go`.

```bash
curl -N -X POST http://localhost:8080/console/api/chat \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "default",
    "model": "gpt-4.1-mini",
    "stream": true,
    "messages": [{"role":"user","content":"Hello from console"}]
  }'
```

Status lookup after completion:

```bash
curl -H "Authorization: Bearer $STRAJA_KEY" \
  http://localhost:8080/v1/straja/requests/<request_id>
```
