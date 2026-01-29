# Built-in console

Source: `internal/console/*`, `internal/server/server.go`

The Straja console is served by the gateway at:

- `/console/` (UI)
- `/console/api/projects` (list projects)
- `/console/api/chat` (send a test chat request)

The console is intended for local debugging. It does not require an API key; instead you send a `project_id` in the request body.

## API: list projects

```bash
curl http://localhost:8080/console/api/projects
```

Response:

```json
[{"id":"default","provider":"openai_default"}]
```

## API: chat

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
