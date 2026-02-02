# Telegram activation sink

Sources: `internal/activation/sink_telegram.go`, `internal/config/config.go`, `internal/config/validate.go`, `internal/server/server.go`

The `telegram` activation sink sends short, redacted alerts to a Telegram chat via the Bot API `sendMessage` endpoint. It is an alert channel only: no raw prompt/response content is sent.

## Configuration

Define the sink under `activation.sinks`:

```yaml
activation:
  enabled: true
  sinks:
    - type: "telegram"
      token_env: "TELEGRAM_BOT_TOKEN"
      chat_id_env: "TELEGRAM_CHAT_ID"
      api_base_url: "https://api.telegram.org"
      disable_web_page_preview: true
      parse_mode: ""
      timeout: "2s"
      rate_limit_per_sec: 1
      min_level: "warn"
      only_categories: ["toolgate", "prompt_injection", "jailbreak", "pii", "data_exfil"]
      send_on_actions: ["block", "warn"]
      max_message_len: 3500
```

### Fields

- `type` (string, required): `telegram`
- `token_env` (string, required): env var name holding the bot token.
- `chat_id_env` (string, required): env var name holding the chat id.
- `api_base_url` (string, optional, default `https://api.telegram.org`).
- `disable_web_page_preview` (bool, optional, default `true`).
- `parse_mode` (string, optional, default empty; only `MarkdownV2` supported).
- `timeout` (duration, optional, default `2s`).
- `rate_limit_per_sec` (int, optional, default `1`).
- `min_level` (string, optional, default `warn`; allowed: `warn`, `block`).
- `only_categories` (string list, optional): if set, alerts only fire when any category matches.
- `send_on_actions` (string list, optional, default `block` + `warn`).
- `max_message_len` (int, optional, default `3500`, max `4096`).

## Message contents

Messages are built from redacted summary fields only:

- timestamp
- project id
- route (responses/toolgate)
- request_id
- action (`block`/`warn`)
- top reason summary (category + action)
- category counts
- toolgate: tool name + rule id + action

If `parse_mode: MarkdownV2` is set, the message text is escaped before sending.

## Required environment variables

Set the token and chat id via the configured env var names:

```
export TELEGRAM_BOT_TOKEN="123:abc"
export TELEGRAM_CHAT_ID="12345678"
```

## Notes

- Delivery is asynchronous via the activation emitter queue and workers.
- If the Telegram response returns `ok=false` or a non-2xx status, delivery is reported as a sink error.
