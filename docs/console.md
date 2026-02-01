# Built-in console

Source: `internal/console/*`, `internal/server/server.go`, `internal/server/console_session.go`

The Straja console is served by the gateway at:

- `/console/` (UI)
- `/console/api/projects` (list projects)
- `/console/api/session` (issue a short-lived console session cookie)
- `/console/api/logout` (clear console session)
- `/console/api/config` (get/save YAML config used by the gateway)
- `/console/api/reload` (reload config; currently returns 501)

The console is intended for local debugging. It does **not** expose API keys to the browser. Instead, the UI requests a short-lived console session cookie tied to a selected `project_id`, then calls the real `/v1/*` endpoints directly.
Console sessions require `STRAJA_CONSOLE_SESSION_SECRET` to be set when the console is enabled. This is just a random string used to sign and verify console session cookies (it is not fetched from anywhere). Set it in `.env` (or your runtime environment) before starting the gateway.

Example:

```bash
openssl rand -hex 32
```

## Console session

Create a console session cookie for a project:

```bash
curl -X POST http://localhost:8080/console/api/session \
  -H "Content-Type: application/json" \
  -d '{"project_id":"default"}'
```

The response sets an HttpOnly cookie (for browser use) and returns a JSON body:

```json
{"status":"ok","project_id":"default","expires_at":"2026-02-01T03:00:00Z"}
```

Once the cookie is set, you can call `/v1/responses`, `/v1/toolgate/check`, and `/v1/requests/{id}` without an `Authorization` header. The server resolves the project via the session cookie.

## API: list projects

```bash
curl http://localhost:8080/console/api/projects
```

Response:

```json
[{"id":"default","provider":"openai_default"}]
```

## API: responses (non-streaming)

After a console session cookie is set, call the real Responses API:

```bash
curl -X POST http://localhost:8080/v1/responses \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4.1-mini",
    "input": "Hello from console"
  }'
```

The response matches the OpenAI Responses API JSON shape.

The console also displays activation payloads via the `X-Straja-Activation` response header. When available, the UI uses activation `request.preview.prompt` and `response.preview.output` as redacted previews.

## UI status labels

The console renders three labels from the activation `summary` object:

- **Request**: `summary.request_final` (`allow`, `redact`, `block`)
- **Response**: `summary.response_final` (`allow`, `redact`, `block`)
- **Note**: `summary.response_note` (e.g., `redaction_applied`, `redaction_suggested`, `unsafe_instruction_detected`, `skipped`)
- **Response guard**: shows `WARN` when response guard matches, with categories and rule IDs on expand

For streaming, the labels appear once the request status endpoint returns the activation payload. The response note is shown next to the Activation panel when present.

## API: responses (streaming)

Add `"stream": true` to stream responses via the Responses API. Streaming is pure SSE passthrough (no custom events). The console UI uses `X-Straja-Request-Id` and the request status API to fetch post-check results after the stream completes.

```bash
curl -N -X POST http://localhost:8080/v1/responses \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4.1-mini",
    "stream": true,
    "input": "Hello from console"
  }'
```

Status lookup after completion:

```bash
curl http://localhost:8080/v1/requests/<request_id>
```

## API: toolgate check

After a console session cookie is set, call the real Toolgate endpoint:

```bash
curl -X POST http://localhost:8080/v1/toolgate/check \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "shell.exec",
    "args": {"command": "rm -rf /"}
  }'
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

## Security notes

- Console sessions are short-lived and scoped to a project.
- API keys are never sent to the browser.
- Do not expose the console publicly; keep it behind localhost or a trusted reverse proxy.
