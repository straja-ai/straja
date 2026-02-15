# Installation

## Binary (recommended)

```bash
curl -fsSL https://straja.ai/install.sh | bash
```

Install a specific version:

```bash
curl -fsSL https://straja.ai/install.sh | bash -s -- --version v0.1.0
```

Install into a custom directory:

```bash
curl -fsSL https://straja.ai/install.sh | bash -s -- --dir /opt/straja
```

Set required environment variables before running:

```bash
export STRAJA_TRUST_KEY="STRAJA-TRUST-..."
export OPENAI_API_KEY="sk-..."
export STRAJA_CONSOLE_SESSION_SECRET="replace-with-a-random-string"
```

Run with:

```bash
./straja/run.sh
```

Update later (recommended):

```bash
./straja/straja update check
./straja/straja update apply
```

If Straja runs as a managed service, apply and restart in one step:

```bash
./straja/straja update apply --restart
```

Notes:

- `update apply` preserves your existing `straja.yaml` by default.
- `--restart` currently supports launchd (macOS) and systemd (Linux).

The default config path is `straja.yaml`. Use `--config /path/to/straja.yaml` to override (see `cmd/straja/main.go`).

Windows (PowerShell, amd64):

```powershell
$asset = "straja_windows_amd64.zip"
Invoke-WebRequest -Uri "https://github.com/straja-ai/straja/releases/latest/download/$asset" -OutFile $asset
Expand-Archive -Path $asset -DestinationPath .
.\straja\straja.exe

# Update later:
.\straja\straja.exe update check
.\straja\straja.exe update apply
```

## From source (Go)

```bash
make build
./bin/straja
```

Common dev commands are in `Makefile`:

- `make run` (loads `.env` if present)
- `make test`
- `make lint`
- `make fmt`
- `make tidy`

## Docker

Build and run the local image:

```bash
make docker-build
```

The image expects:

- Config at `/etc/straja/straja.yaml`
- Intel dir at `/var/lib/straja/intel`
- Bundle cache at `/var/lib/straja/bundles`

Example run (adjust host paths/ports):

```bash
docker run --rm \
  -p 8080:8080 \
  -v "$(pwd)/straja.yaml:/etc/straja/straja.yaml:ro" \
  -v "$(pwd)/intel:/var/lib/straja/intel" \
  -v "$(pwd)/bundles:/var/lib/straja/bundles" \
  -e STRAJA_INTEL_DIR="/var/lib/straja/intel" \
  -e STRAJA_BUNDLE_CACHE_DIR="/var/lib/straja/bundles" \
  -e STRAJA_BUNDLE_DIR="/var/lib/straja/bundles/strajaguard_v1" \
  -e OPENAI_API_KEY="sk-..." \
  -e STRAJA_TRUST_KEY="your-trust-key" \
  -e STRAJA_CONSOLE_SESSION_SECRET="replace-with-a-random-string" \
  straja:local
```

See `Dockerfile` and `Makefile` target `docker-run` for the exact runtime wiring.
