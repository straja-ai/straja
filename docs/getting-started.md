# Getting started

This is the shortest path to a first request against Straja.

## 1) Install the binary

```bash
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "$os" in
  linux|darwin) ;;
  *) echo "Unsupported OS: $os" >&2; exit 1 ;;
esac

case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "Unsupported arch: $arch" >&2; exit 1 ;;
esac

asset="straja_${os}_${arch}.tar.gz"
curl -L -o "${asset}" "https://github.com/straja-ai/straja/releases/latest/download/${asset}"
tar -xzf "${asset}"
```

Verify checksum (recommended):

```bash
curl -LO "https://github.com/straja-ai/straja/releases/latest/download/checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
  sha_cmd="sha256sum"
else
  sha_cmd="shasum -a 256"
fi
grep "  ${asset}$" checksums.txt | $sha_cmd -c -
```

## 2) Set your Straja license key

```bash
export STRAJA_LICENSE_KEY="STRAJA-FREE-..."
```

If you do not have a license key, get a free one at `https://straja.ai`.

## 3) Export your provider API key

Straja reads upstream provider keys from environment variables.

```bash
export OPENAI_API_KEY="sk-..."
```

## 4) Set a console session secret

The built-in console requires a session secret for signing cookies. Set it in your environment before starting Straja.

```bash
export STRAJA_CONSOLE_SESSION_SECRET="replace-with-a-random-string"
```

## 5) Review the included `straja.yaml`

The release archive includes a starter `straja.yaml`. It should work out of the box, but review it and tweak defaults (ports, project IDs, API keys) if needed.

## 6) Run the gateway

```bash
./straja/run.sh
```

## 7) Open the console or send your first request

Open the console at `http://localhost:8080/console/`, or send an API request:

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer local-dev-key-123" \
  -d '{
    "model": "gpt-4.1-mini",
    "messages": [{"role": "user", "content": "Hello from Straja!"}]
  }'
```

You should receive an OpenAI-compatible JSON response.

## Notes

- If the config file does not exist, Straja loads defaults (`internal/config/config.go`), but `config.Validate` will fail because there are no providers/projects configured.
- Project API keys must be unique across projects (`internal/auth/auth.go`).
