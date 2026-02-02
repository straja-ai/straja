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

1. Install the binary (download the latest release archive).
2. Set your Straja license key.
3. Export your provider API key (example below uses OpenAI).
4. Set a console session secret.
5. Review the included `straja.yaml`.
6. Run the gateway.
7. Open the console or send your first request.

OpenAI SDKs work unchanged. No changes to model call logic are required.

See the documentation below for exact commands and examples.

## Documentation

- [Getting started](docs/getting-started.md)
- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [Environment variables](docs/environment-variables.md)
- [Docker](docs/docker.md)
- [Built-in console](docs/console.md)
- [Activation events and sinks](docs/activation.md)
- [Telegram activation sink](docs/activation-telegram.md)
- [StrajaGuard v1 intel bundle](docs/strajaguard-v1.md)
- [Toolgate API](docs/toolgate.md)
- [OpenClaw integration](docs/integrations/openclaw.md)
- [Load testing and mock provider](docs/load-testing.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Security considerations](docs/security.md)
- [Releasing](docs/releasing.md)

## Status

This project is under active development. APIs and configuration may evolve as the gateway matures.

## License

MIT

## Contact

For questions, feedback, or early usage discussions, contact **hello@straja.ai**.
