# Built-in console

Source: `internal/console/*`, `internal/server/server.go`, `internal/server/console_stream.go`

The Straja console is served by the gateway at:

- `/console/` (UI)
- `/console/api/projects` (list projects)
- `/console/api/chat` (send a test chat request; supports streaming)
- `/console/api/requests/{request_id}?project_id=...` (request status for console streaming)
- `/console/api/config` (get/save YAML config used by the gateway)
- `/console/api/reload` (reload config; currently returns 501)

The console is intended for local debugging. It does not require an API key; instead you send a `project_id` in the request body.
The UI also stores a local request history in the browser (localStorage) for the Requests and Overview pages.

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
When available, the UI uses activation `request.preview.prompt` and `response.preview.output` as redacted previews.

## UI status labels

The console renders three labels from the activation `summary` object:

- **Request**: `summary.request_final` (`allow`, `redact`, `block`)
- **Response**: `summary.response_final` (`allow`, `redact`, `block`)
- **Note**: `summary.response_note` (e.g., `redaction_applied`, `redaction_suggested`, `unsafe_instruction_detected`, `skipped`)
- **Response guard**: shows `WARN` when response guard matches, with categories and rule IDs on expand

For streaming, the labels appear once the request status endpoint returns the activation payload. The response note is shown next to the Activation panel when present.

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

Console helper (no API key, requires `project_id`):

```bash
curl http://localhost:8080/console/api/requests/<request_id>?project_id=default
```

## API: config (get/save)

Fetch current gateway config (YAML):

```bash
curl http://localhost:8080/console/api/config
```

Save updated YAML (validated server-side):

```bash
curl -X POST http://localhost:8080/console/api/config \
  -H "Content-Type: text/yaml" \
  --data-binary @straja.yaml
```

## API: reload (not supported)

```bash
curl -X POST http://localhost:8080/console/api/reload
```

Currently responds with `501` and `reload not supported; restart gateway`.
