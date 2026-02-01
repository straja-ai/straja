# Toolgate API

Toolgate provides pre-execution safety decisions for tool calls. It is designed for agent runtimes that need an allow/warn/block verdict before running a tool.

Toolgate is distinct from response scanning: it evaluates **tool inputs**, not model outputs.

## Supported tool types

Toolgate accepts generic tool descriptors and infers types from `tool_name`:

- **shell** (e.g. `shell.exec`)
- **http** (e.g. `http.request`)
- **filesystem** (e.g. `filesystem.read`)
- **nodes.run** (delegates to `args.tool_type` if provided)

## Decision model

Toolgate returns one of:

- `allow`
- `warn`
- `block`

Privilege escalation patterns are **blocked** in `elevated_only` mode and **warned** in `all_tools` mode.

## API reference

### POST `/v1/toolgate/check`

Request body:

```json
{
  "tool_name": "shell.exec",
  "args": {"command": "rm -rf /"},
  "context": {
    "project_id": "demo",
    "mode": "elevated_only",
    "source": "custom"
  }
}
```

Response (200):

```json
{
  "request_id": "...",
  "decision": "warn",
  "hits": [
    {
      "rule_id": "...",
      "category": "data_exfil",
      "action": "warn",
      "confidence": 1,
      "sources": ["heuristic:tool_gate", "rule:<rule_id>"],
      "evidence": "..."
    }
  ],
  "normalized": {
    "available": true,
    "command": "rm -rf /"
  },
  "latency_ms": 3.2
}
```

Error (403 block):

```json
{
  "error": {
    "message": "Tool execution blocked by Straja toolgate",
    "type": "straja_tool_policy_violation",
    "code": "tool_blocked",
    "rule_id": "rm_rf_root",
    "category": "unsafe_action",
    "request_id": "..."
  }
}
```

Headers:

- `X-Straja-Request-Id`: request id for follow-up status
- `X-Straja-Activation`: optional activation payload

### POST `/v1/toolgate/explain`

Disabled by default. Enable with `toolgate_api.allow_explain: true`.

Returns additional debug fields **without** exposing raw rule expressions:

- `matched_on`: `original` or `normalized`
- `evidence_span`: `[start, end]`

### GET `/v1/requests/{request_id}`

Returns the activation event for the toolgate check.

## Examples (no raw rule expressions)

- Uploading a local file with `curl` → **block**
- Reading `~/.ssh/id_rsa` → **block**
- `sudo apt install` → **warn** in `all_tools`, **block** in `elevated_only`
- `rm -rf /` → **block**
- `ls -la` → **allow**

## Integration patterns

- Call `/v1/toolgate/check` before executing a tool.
- If **block**, refuse execution and surface the reason to the user.
- If **warn**, allow execution but log the hit.
- If **allow**, proceed normally.

## Security & privacy notes

- Evidence is truncated and redacted.
- Toolgate requires an API key (Bearer token).
- The full rule expressions are intentionally not published to reduce evasion.

## Configuration reference

```yaml
tool_gate:
  enabled: true
  mode: elevated_only
  allowlist_hosts: []
  allowlist_commands: []

toolgate_api:
  allow_explain: false
```

Defaults are defined in `internal/config/config.go`.
