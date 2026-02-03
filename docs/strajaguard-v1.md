# StrajaGuard bundles

Sources: `internal/strajaguard/*`, `internal/server/server.go`, `internal/config/config.go`

StrajaGuard is the local ML classifier used by the security layer. It runs via ONNX Runtime and uses a signed bundle downloaded from the trust service.

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

The specialists definitions are loaded from an embedded default config (built into the gateway binary). You can override it with `strajaguard.specialists.config_path` if you want to customize the specialists list.

### Overriding specialists config

```yaml
strajaguard:
  specialists:
    config_path: "/path/to/strajaguard_specialists.yaml"
```

## Paths

- `intel.strajaguard_v1.intel_dir` (default `./intel`) controls the base directory.
- The bundle path is `<intel_dir>/<family>` unless `security.bundle_dir` is explicitly set.
- `security.bundle_dir` is used by the model loader; it is aligned to `intel_dir` when needed.

See `internal/config/config.go` and `internal/server/server.go` for the path resolution logic.

## Trust key resolution

A trust key is required to enable Straja’s signed safety models. It ensures the integrity and authenticity of local intelligence bundles. All models run locally.

Trust keys are resolved via `resolveTrust` in `internal/config/config.go`:

1) Env var named by `intelligence.trust_key_env` (default `STRAJA_TRUST_KEY`)
2) `intel.strajaguard_v1.trust_key`
3) `intelligence.trust_key`

Placeholder values such as `STRAJA-TRUST-XXXX` are treated as empty.

Without a trust key, StrajaGuard intelligence is disabled and the gateway runs regex-only detection.

Offline verification uses the embedded Ed25519 public key (`internal/trust/trust.go`), which can be overridden with `STRAJA_TRUST_PUBLIC_KEY`.

## Online validation and bundle download

When a trust key is present, StrajaGuard validates it against:

- `intel.strajaguard_v1.trust_server_base_url` (default `https://straja.ai`)
- Endpoint: `POST /api/trustkey/validate`

If validation succeeds, StrajaGuard downloads:

- `manifest.json`
- `manifest.sig`
- bundle files listed in the manifest

All downloads are authenticated with a short-lived bundle token from the trust validation response. See `internal/strajaguard/bundle.go`.

## Signature and integrity verification

- Manifests are verified with Ed25519 signatures (`manifest.sig`).
- The public key can be overridden with `STRAJAGUARD_MANIFEST_PUBLIC_KEY`.
- Each file is verified by SHA-256 and size checks from the manifest.
- Paths are sanitized to prevent traversal outside the bundle dir.

See `internal/strajaguard/bundle.go` and `internal/strajaguard/verify.go`.

## Caching and offline behavior

- Bundle state is stored in `state.json` (current + previous version).
- Validation metadata is stored in `validation_meta.json` (last validated time, trust fingerprint).

When online validation fails:

- Invalid trust key => StrajaGuard disabled (`disabled_invalid_trust_key`).
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
