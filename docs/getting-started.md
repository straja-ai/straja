# Getting started

This is the shortest path to a first request against Straja.

## 1) Install the binary

```bash
curl -LO https://github.com/straja-ai/straja/releases/latest/download/straja
chmod +x straja
```

## 2) Export your provider API key

Straja reads upstream provider keys from environment variables.

```bash
export OPENAI_API_KEY="sk-..."
```

## 3) Create a minimal `straja.yaml`

```yaml
server:
  addr: ":8080"

default_provider: "openai_default"

providers:
  openai_default:
    type: "openai"
    base_url: "https://api.openai.com/v1"
    api_key_env: "OPENAI_API_KEY"

projects:
  - id: "default"
    provider: "openai_default"
    api_keys:
      - "local-dev-key-123"
```

## 4) Run the gateway

```bash
./straja --config straja.yaml
```

Flags are defined in `cmd/straja/main.go`:

- `--config` (default: `straja.yaml`)
- `--addr` (overrides `server.addr`)

## 5) Send your first request

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer local-dev-key-123" \
  -d '{
    "model": "gpt-4.1-mini",
    "messages": [{"role": "user", "content": "Hello from Straja!"}]
  }'
```

You should receive an OpenAI-compatible JSON response.

## Notes

- If the config file does not exist, Straja loads defaults (`internal/config/config.go`), but `config.Validate` will fail because there are no providers/projects configured.
- Project API keys must be unique across projects (`internal/auth/auth.go`).
