# StrajaGuard bundles

Sources: `internal/strajaguard/*`, `internal/server/server.go`, `internal/config/config.go`

StrajaGuard is the local ML classifier used by the security layer. It runs via ONNX Runtime and uses a signed bundle downloaded from the license server.

## Enablement

StrajaGuard is enabled only when both are true:

- `security.enabled: true`
- `intel.strajaguard_v1.enabled: true`

If either is false, StrajaGuard ML is disabled and the gateway runs regex-only detection.

## Bundle family selection

The bundle family is selected via:

```yaml
intel:
  strajaguard:
    family: strajaguard_v1_specialists
```

Supported values:

- `strajaguard_v1` (legacy multi-label classifier)
- `strajaguard_v1_specialists` (prompt injection + jailbreak + PII NER specialists)

If omitted, StrajaGuard defaults to `strajaguard_v1`.

## Bundle layout

### `strajaguard_v1`

A bundle directory is considered valid when these files exist (`internal/strajaguard/lifecycle.go`):

- `manifest.json`
- `manifest.sig`
- `strajaguard_v1.onnx` (or `strajaguard_v1.int8.onnx`)
- `label_map.json`
- `thresholds.yaml`
- `tokenizer/vocab.txt`

### `strajaguard_v1_specialists`

A specialists bundle contains three model subdirectories:

- `prompt_injection/` (sequence classification)
- `jailbreak/` (sequence classification)
- `pii_ner/` (token classification / NER)

Each specialist directory must include:

- `model.int8.onnx` or `model.onnx`
- `tokenizer/` assets (tokenizer config + vocab)
- `config.json` (Hugging Face model config)

The specialists definitions are loaded from `configs/strajaguard_specialists.yaml`.

## Paths

- `intel.strajaguard_v1.intel_dir` (default `./intel`) controls the base directory.
- The bundle path is `<intel_dir>/<family>` unless `security.bundle_dir` is explicitly set.
- `security.bundle_dir` is used by the model loader; it is aligned to `intel_dir` when needed.

See `internal/config/config.go` and `internal/server/server.go` for the path resolution logic.

## License resolution

License keys are resolved via `resolveLicense` in `internal/config/config.go`:

1) Env var named by `intelligence.license_key_env` (default `STRAJA_LICENSE_KEY`)
2) `intel.strajaguard_v1.license_key`
3) `intelligence.license_key`

Placeholder values such as `STRAJA-FREE-XXXX` are treated as empty.

Offline verification uses the embedded Ed25519 public key (`internal/license/license.go`), which can be overridden with `STRAJA_LICENSE_PUBLIC_KEY`.

## Online validation and bundle download

When a license key is present, StrajaGuard validates it against:

- `intel.strajaguard_v1.license_server_base_url` (default `https://straja.ai`)
- Endpoint: `POST /api/license/validate`

If validation succeeds, StrajaGuard downloads:

- `manifest.json`
- `manifest.sig`
- bundle files listed in the manifest

All downloads are authenticated with a short-lived bundle token from the license validation response. See `internal/strajaguard/bundle.go`.

## Signature and integrity verification

- Manifests are verified with Ed25519 signatures (`manifest.sig`).
- The public key can be overridden with `STRAJAGUARD_MANIFEST_PUBLIC_KEY`.
- Each file is verified by SHA-256 and size checks from the manifest.
- Paths are sanitized to prevent traversal outside the bundle dir.

See `internal/strajaguard/bundle.go` and `internal/strajaguard/verify.go`.

## Caching and offline behavior

- Bundle state is stored in `state.json` (current + previous version).
- Validation metadata is stored in `validation_meta.json` (last validated time, license fingerprint).

When online validation fails:

- Invalid license => StrajaGuard disabled (`disabled_invalid_license`).
- Network error and a cached bundle exists => verify integrity and load cached bundle (`offline_cached_bundle`).
- Network error with no cached bundle => `disabled_missing_bundle`.
- Any other validation failure => `disabled_invalid_bundle`.

If `require_ml: true` and `allow_regex_only: false`, StrajaGuard startup failures are fatal (`redact.Fatalf`) instead of falling back to regex-only.

## ONNX Runtime dependency

StrajaGuard requires the ONNX Runtime shared library. It is located via:

- `ONNXRUNTIME_SHARED_LIBRARY_PATH` if set, otherwise a search in standard locations.

If the library is not found, StrajaGuard ML is disabled and the gateway runs regex-only detection.

## Runtime tuning

Runtime settings are resolved by `internal/strajaguard/model.go`:

Defaults (when unset):

- `max_sessions`: 2
- `intra_threads`: 4
- `inter_threads`: 1

Precedence: YAML `strajaguard.*` > env `STRAJA_GUARD_*` > defaults.

- `strajaguard.max_sessions` / `STRAJA_GUARD_MAX_SESSIONS`
- `strajaguard.intra_threads` / `STRAJA_GUARD_INTRA_THREADS`
- `strajaguard.inter_threads` / `STRAJA_GUARD_INTER_THREADS`
