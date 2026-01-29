# Configuration reference

Source of truth: `internal/config/config.go` and `internal/config/validate.go`.

## Load behavior and precedence

1) Defaults are applied (`defaultConfig`).
2) YAML file overrides defaults (`config.Load`).
3) Additional defaults are applied for zero values (`applyDefaults`).
4) Selected environment variables override YAML (see [Environment variables](environment-variables.md)).

If the config file path does not exist, `config.Load` returns defaults without error, but `config.Validate` will fail unless required fields are present.

## Top-level keys

```yaml
server: {}
providers: {}
default_provider: ""
projects: []
logging: {}
activation: {}
telemetry: {}
policy: {}
intelligence: {}
security: {}
intel: {}
strajaguard: {}
```

## `server`

Source: `internal/config/config.go` (ServerConfig)

- `addr` (string, default `":8080"`)
- `read_header_timeout` (duration, default `5s`)
- `read_timeout` (duration, default `30s`)
- `write_timeout` (duration, default `120s`)
- `idle_timeout` (duration, default `60s`)
- `max_request_body_bytes` (int64, default `2097152` = 2MiB)
- `max_non_stream_response_bytes` (int64, default `4194304` = 4MiB)
- `max_in_flight_requests` (int, default `200`)
- `upstream_timeout` (duration, default `60s`)
- `max_messages` (int, default `64`)
- `max_total_message_chars` (int, default `32000`)

Environment variable overrides for these fields accept standard Go duration strings (`"30s"`, `"5m"`) and fall back to seconds if the value is a plain integer. Env overrides apply to a subset of fields (see env docs).

## `providers`

Source: `internal/config/config.go` (ProviderConfig) and `internal/server/server.go` (buildProviderRegistry)

Each provider entry defines an upstream.

- `type` (string, required). Supported values: `"openai"`, `"mock"`.
- `base_url` (string, optional; for OpenAI defaults to `https://api.openai.com/v1` in provider code)
- `api_key_env` (string, required for `openai` unless `api_key` is set; name of env var containing upstream key)
- `api_key` (string, optional fallback when env var is empty)
- `allowed_models` (string list, optional allowlist)
- `allow_private_networks` (bool, default `false`; when `false`, private/localhost base URLs are rejected)

Notes:

- Validation enforces `type` and (for `openai`) presence of `api_key_env` or `api_key`, plus a valid `base_url` scheme. See `internal/config/validate.go`.
- If `allow_private_networks` is `false`, private/loopback hosts are blocked to reduce SSRF risk.
- `mock` providers start a local mock upstream (see `internal/mockprovider/mockprovider.go`).

## `default_provider`

- If empty and **exactly one** provider exists, it is set automatically.
- Validation requires a non-empty value that exists in `providers`.

## `projects`

Source: `internal/config/config.go` (ProjectConfig) and `internal/auth/auth.go`

- `id` (string, required)
- `provider` (string, optional; defaults to `default_provider`)
- `api_keys` (string list, required when `security.enabled: true`)
- `allowed_models` (string list, optional allowlist)

Notes:

- Project API keys must be unique across all projects.
- Model allowlist precedence: project allowlist wins over provider allowlist.

## `logging`

Source: `internal/config/config.go` and `internal/server/server.go`

- `activation_level` (string, default `"metadata"`)
  - `metadata`: no prompt/response previews
  - `redacted`: previews with basic redaction
  - `full`: previews with full content (still redacted by log redactor)

## `activation`

Source: `internal/config/config.go`, `internal/activation/*`, and `internal/server/server.go`

- `enabled` (bool, default `false`)
- `queue_size` (int, default `1000`)
- `workers` (int, default `1`)
- `shutdown_timeout` (duration, default `2s`)
- `sinks` (list, default empty)

`activation.sinks` entries:

- `type` (string, required): `file_jsonl` or `webhook`
- `path` (string, required for `file_jsonl`)
- `url` (string, required for `webhook`)
- `headers` (map string->string, optional for `webhook`)
- `timeout` (duration, optional for `webhook`, default `2s`)

## `telemetry`

Source: `internal/config/config.go` and `internal/telemetry/telemetry.go`

- `enabled` (bool, default `false`)
- `endpoint` (string, default empty)
- `protocol` (string, default `"grpc"`; allowed: `grpc`, `http`)

Validation requires `endpoint` if `enabled: true`.

## `policy`

Source: `internal/config/config.go` and `internal/policy/policy.go`

Action values are parsed as: `block`, `log`, `ignore`, `redact`. Unknown values fall back to defaults.

- `banned_words` (string, default `"block"`)
- `banned_words_list` (string list, default empty)
- `pii` (string, default `"block"`)
- `pii_entities` (object, defaults to all `true` if omitted entirely)
  - `email`, `phone`, `credit_card`, `iban`, `tokens`
- `injection` (string, default `"block"`)
- `prompt_injection` (string, default `"block"`)
- `jailbreak` (string, default `"block"`)
- `toxicity` (string, default `"log"`)

When `security.enabled` is `true`, PII/prompt-injection/jailbreak are primarily governed by `security.*` (ML + regex) and only fall back to the legacy policy actions when `security.enabled` is `false`.

## `intelligence`

Source: `internal/config/config.go` and `internal/server/server.go`

- `enabled` (bool, default `true`)
- `license_key` (string, default empty)
- `license_server_url` (string, default empty)
- `bundle_cache_dir` (string, default `"~/.straja/bundles"`)
- `license_key_env` (string, default `"STRAJA_LICENSE_KEY"`)
- `auto_update` (bool, default `true`)
- `update_check_interval` (string, default `"6h"`)

Notes:

- `license_key_env` controls which env var name is checked for a license key. The env value (if set) overrides YAML values. Placeholder values such as `STRAJA-FREE-XXXX` are treated as empty.
- `license_server_url` is used for an optional online license validation at startup (`internal/server/server.go`). If empty, no request is made.
- `bundle_cache_dir`, `auto_update`, and `update_check_interval` are defined but not referenced by runtime code in this repo (current no-op).
- Setting `intelligence.enabled: false` swaps in a no-op intel engine, so regex-based detections and output redaction do not run.

## `security`

Source: `internal/config/config.go`, `internal/safety/policy_eval.go`

- `enabled` (bool, default `true`)
- `bundle_dir` (string, default `"./intel/strajaguard_v1"`)
- `seq_len` (int, default `256`)

### `security.prompt_injection`, `security.jailbreak`, `security.data_exfil`

Type: `SecurityCategoryConfig`

- `regex_enabled` (bool, default `true`)
- `ml_enabled` (bool, default `true`)
- `ml_warn_threshold` (float32, default per category)
- `ml_block_threshold` (float32, default per category)
- `action_on_block` (string, default `"block"`)
- `action_on_regex_hit` (string, default empty)

If `action_on_regex_hit` is empty, regex hits use `action_on_block`. ML warn thresholds emit `"warn"` actions.

Defaults:

- prompt_injection: warn `0.60`, block `0.80`
- jailbreak: warn `0.60`, block `0.80`
- data_exfil: warn `0.55`, block `0.75`

### `security.pii`

Type: `PIICategoryConfig`

- `regex_enabled` (bool, default `true`)
- `ml_enabled` (bool, default `true`)
- `ml_warn_threshold` (float32, default `0.50`)
- `action_on_regex_hit` (string, default `"redact"`)
- `action_on_ml_only` (string, default `"log"`)

### `security.secrets`

Type: `SecretsCategoryConfig`

- `regex_enabled` (bool, default `true`)
- `ml_enabled` (bool, default `true`)
- `ml_warn_threshold` (float32, default `0.50`)
- `ml_block_threshold` (float32, default `0.85`)
- `action_on_regex_hit` (string, default `"block_and_redact"`)
- `action_on_ml_only` (string, default `"log"`)

## `intel`

Source: `internal/config/config.go`

```yaml
intel:
  strajaguard_v1: {}
```

`intel.strajaguard_v1` options:

- `enabled` (bool, default `true`)
- `license_server_base_url` (string, default `"https://straja.ai"`)
- `license_key` (string, default empty)
- `request_timeout_seconds` (int, default `60`) (legacy fallback)
- `license_validate_timeout_seconds` (int, default `10`)
- `bundle_download_timeout_seconds` (int, default `30`)
- `intel_dir` (string, default `"./intel"`)
- `version_file` (string, default `"version"`) (defined; currently only used by helper functions, not by server startup flow)
- `allow_regex_only` (bool, default `false`) (env override: `STRAJA_ALLOW_REGEX_ONLY`)
- `update_on_start` (bool, default `true`) (defined, currently not referenced by runtime code)
- `require_ml` (bool, default `true`) (env override: `STRAJA_REQUIRE_ML`)

Timeout inheritance:

- If `license_validate_timeout_seconds` or `bundle_download_timeout_seconds` are zero, they fall back to `request_timeout_seconds` (if set), otherwise to their defaults.

## `strajaguard`

Source: `internal/config/config.go` and `internal/strajaguard/model.go`

Runtime settings for the StrajaGuard ONNX runtime:

- `max_sessions` (int, default `0` -> runtime default 2)
- `intra_threads` (int, default `0` -> runtime default 4)
- `inter_threads` (int, default `0` -> runtime default 1)

Precedence for runtime settings: YAML `strajaguard.*` > env `STRAJA_GUARD_*` > internal defaults.
