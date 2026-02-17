# Straja Gateway Developer Docs

This documentation set is generated from the current repository. Every option and behavior described here is backed by code in this repo.

## Contents

- [Getting started](getting-started.md)
- [Auto-start on macOS (LaunchDaemon)](autostart-macos-launchdaemon.md)
- [Installation](installation.md)
- [Configuration reference](configuration.md)
- [Environment variables](environment-variables.md)
- [Docker setup and production notes](docker.md)
- [Built-in console](console.md)
- [OpenAI API integration](integrations/openai.md)
- [OpenClaw integration](integrations/openclaw.md)
- [Claude API integration](integrations/claude.md)
- [Load testing and mock provider](load-testing.md)
- [Activation events and sinks](activation.md)
- [Telegram activation sink](activation-telegram.md)
- [StrajaGuard v1 intel bundle](strajaguard-v1.md)
- [Vault Phases 1-5 (strajad)](vault-phase1.md)
- [Troubleshooting](troubleshooting.md)
- [Security considerations](security.md)
- [Releasing](releasing.md)

## Source of truth

- Configuration structs, defaults, and env parsing: `internal/config/config.go`
- Validation rules: `internal/config/validate.go`
- HTTP server & routes: `internal/server/server.go`
- Vault daemon & MCP routes: `internal/strajad/*`
- Activation events & sinks: `internal/activation/*`
- StrajaGuard bundles & runtime: `internal/strajaguard/*`
- Docker image: `Dockerfile`
- Load test tooling: `Makefile`, `tools/loadtest/chat_completion.js`
