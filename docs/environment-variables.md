# Environment variables

All env vars listed here are referenced directly in code.

## Server overrides

Source: `internal/config/config.go`

- `STRAJA_READ_HEADER_TIMEOUT`
- `STRAJA_READ_TIMEOUT`
- `STRAJA_WRITE_TIMEOUT`
- `STRAJA_IDLE_TIMEOUT`
- `STRAJA_MAX_REQUEST_BODY_BYTES`
- `STRAJA_MAX_NON_STREAM_RESPONSE_BYTES`
- `STRAJA_MAX_IN_FLIGHT_REQUESTS`
- `STRAJA_UPSTREAM_TIMEOUT`

Values follow Go `time.Duration` syntax; if a plain integer is provided for timeouts, it is interpreted as seconds.

Example:

```bash
export STRAJA_READ_TIMEOUT=45s
export STRAJA_MAX_REQUEST_BODY_BYTES=3145728
```

## Telemetry

Source: `internal/config/config.go`

- `OTEL_EXPORTER_OTLP_ENDPOINT` (overrides `telemetry.endpoint`)
- `OTEL_EXPORTER_OTLP_PROTOCOL` (overrides `telemetry.protocol`, expects `grpc` or `http`)

Example:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
```

## License keys and verification

Source: `internal/config/config.go`, `internal/license/license.go`

- `STRAJA_LICENSE_KEY` (default license env name; can be changed via `intelligence.license_key_env`)
- `STRAJA_LICENSE_PUBLIC_KEY` (override the embedded license public key)

Precedence for the license key is described in `configuration.md`.

Example:

```bash
export STRAJA_LICENSE_KEY="STRAJA-FREE-..."
```

## Bundle paths

Source: `internal/config/config.go`

- `STRAJA_BUNDLE_CACHE_DIR` (overrides `intelligence.bundle_cache_dir`)
- `STRAJA_BUNDLE_DIR` (overrides `security.bundle_dir`)
- `STRAJA_INTEL_DIR` (overrides `intel.strajaguard_v1.intel_dir`)

Example:

```bash
export STRAJA_INTEL_DIR=/var/lib/straja/intel
export STRAJA_BUNDLE_DIR=/var/lib/straja/intel/strajaguard_v1
export STRAJA_BUNDLE_CACHE_DIR=/var/lib/straja/bundles
```

## StrajaGuard v1 bundle controls

Source: `internal/config/config.go`

- `STRAJA_ALLOW_REGEX_ONLY` (overrides `intel.strajaguard_v1.allow_regex_only`)
- `STRAJA_UPDATE_ON_START` (overrides `intel.strajaguard_v1.update_on_start`)
- `STRAJA_REQUIRE_ML` (overrides `intel.strajaguard_v1.require_ml`)
- `STRAJA_LICENSE_VALIDATE_TIMEOUT_SECONDS` (overrides `intel.strajaguard_v1.license_validate_timeout_seconds`)
- `STRAJA_BUNDLE_DOWNLOAD_TIMEOUT_SECONDS` (overrides `intel.strajaguard_v1.bundle_download_timeout_seconds`)

## StrajaGuard runtime tuning

Source: `internal/strajaguard/model.go`

- `STRAJA_GUARD_MAX_SESSIONS`
- `STRAJA_GUARD_INTRA_THREADS`
- `STRAJA_GUARD_INTER_THREADS`

These are used only if the corresponding `strajaguard.*` YAML fields are zero.

Example:

```bash
export STRAJA_GUARD_MAX_SESSIONS=2
export STRAJA_GUARD_INTRA_THREADS=4
export STRAJA_GUARD_INTER_THREADS=1
```

## ONNX Runtime shared library

Source: `internal/strajaguard/model.go`

- `ONNXRUNTIME_SHARED_LIBRARY_PATH` (absolute path to the shared library, if not in standard locations)

## StrajaGuard bundle signature key

Source: `internal/strajaguard/bundle.go`

- `STRAJAGUARD_MANIFEST_PUBLIC_KEY` (base64-encoded Ed25519 key for manifest verification)

## Mock provider

Source: `internal/mockprovider/mockprovider.go`

- `MOCK_PROVIDER_PORT` (default `18080`)
- `MOCK_DELAY_MS` (default `50`)

## Build/version metadata

Source: `internal/server/server.go`

- `STRAJA_VERSION` (sent in online license validation payloads)

## Provider API keys

Source: `internal/server/server.go`

- The name of each provider key env var is defined in your config under `providers.<name>.api_key_env` (e.g., `OPENAI_API_KEY`).
