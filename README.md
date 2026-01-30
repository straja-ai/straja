# Straja Gateway

Straja is a **local, OpenAI-compatible AI gateway** that runs inside your infrastructure and sits between your applications and upstream LLM providers.

It is designed to give teams control, visibility, and safety over AI traffic without changing how applications call models.

Straja provides:

- **Security** – PII and secrets detection, plus prompt-injection and jailbreak heuristics  
- **Privacy** – Applications never see upstream provider API keys  
- **Observability** – Structured activation events for every request  
- **Routing** – Projects mapped to providers (OpenAI today, more later)  
- **Drop-in DX** – Standard OpenAI SDKs and request formats, with a different base URL and key  

## Key concepts (high level)

- **Gateway**  
  An OpenAI-shaped HTTP surface that routes requests to configured providers using per-project credentials.

- **Policies**  
  Pre- and post-model checks that can allow, block, log, or redact requests and responses.

- **StrajaGuard v1**  
  Optional local ML classifier for security signals, delivered as signed bundles and executed via ONNX Runtime.

- **Activation events**  
  Canonical per-request telemetry emitted via headers, logs, and optional sinks for downstream processing.

## Quickstart (minimal)

1. Install the Straja binary or run it via Docker.
2. Create a minimal `straja.yaml` configuration.
3. Start the gateway and send a standard OpenAI `POST /v1/chat/completions` request using a project API key.

OpenAI SDKs work unchanged. No changes to model call logic are required.

See the documentation below for exact commands and examples.

## Documentation

- [Getting started](docs/getting-started.md)
- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [Environment variables](docs/environment-variables.md)
- [Docker](docs/docker.md)
- [StrajaGuard v1](docs/strajaguard-v1.md)
- [Activation events](docs/activation.md)
- [Moltbot + Codex integration](docs/integrations/moltbot-codex.md)
- [Load testing](docs/load-testing.md)

## Status

This project is under active development. APIs and configuration may evolve as the gateway matures.

## License

MIT

## Contact

For questions, feedback, or early usage discussions, contact **hello@straja.ai**.
