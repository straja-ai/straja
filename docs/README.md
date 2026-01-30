# Straja Gateway Developer Docs

This documentation set is generated from the current repository. Every option and behavior described here is backed by code in this repo.

## Contents

- [Getting started](getting-started.md)
- [Installation](installation.md)
- [Configuration reference](configuration.md)
- [Environment variables](environment-variables.md)
- [Docker setup and production notes](docker.md)
- [Built-in console](console.md)
- [Moltbot + Codex integration](integrations/moltbot-codex.md)
- [Load testing and mock provider](load-testing.md)
- [Activation events and sinks](activation.md)
- [StrajaGuard v1 intel bundle](strajaguard-v1.md)
- [Troubleshooting](troubleshooting.md)
- [Security considerations](security.md)

## Source of truth

- Configuration structs, defaults, and env parsing: `internal/config/config.go`
- Validation rules: `internal/config/validate.go`
- HTTP server & routes: `internal/server/server.go`
- Activation events & sinks: `internal/activation/*`
- StrajaGuard bundles & runtime: `internal/strajaguard/*`
- Docker image: `Dockerfile`
- Load test tooling: `Makefile`, `tools/loadtest/chat_completion.js`
