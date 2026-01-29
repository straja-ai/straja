# Load testing and mock provider

Sources: `Makefile`, `tools/loadtest/chat_completion.js`, `internal/mockprovider/mockprovider.go`

## Load testing with k6

The k6 script lives at `tools/loadtest/chat_completion.js` and is wired via Makefile targets.

Environment variables for the script:

- `STRAJA_BASE_URL` (default `http://localhost:8080`)
- `STRAJA_API_KEY` (default `local-dev-key-123`)
- `STRAJA_QPS` (default `20`)
- `STRAJA_DURATION` (default `60s`)
- `STRAJA_CONCURRENCY` (default `10`)

Run:

```bash
make loadtest
```

## Mock provider

The mock provider is an OpenAI-compatible local upstream used to isolate Straja overhead.

- Config example: `examples/straja.mock.yaml`
- Provider type: `mock` (starts a local mock server)
- Env knobs:
  - `MOCK_PROVIDER_PORT` (default `18080`)
  - `MOCK_DELAY_MS` (default `50`)

Make targets:

- `make loadtest-mock` (starts Straja with the mock provider and runs k6)
- `make loadtest-mock-delay` (same, with a fixed 50ms mock delay)

These targets start the gateway on port `8080` and use `STRAJA_API_KEY=mock-api-key` for the mock project.
