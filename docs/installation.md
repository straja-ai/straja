# Installation

## Binary (recommended)

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

Run with:

```bash
./straja/run.sh --config straja.yaml
```

Windows (PowerShell, amd64):

```powershell
$asset = "straja_windows_amd64.zip"
Invoke-WebRequest -Uri "https://github.com/straja-ai/straja/releases/latest/download/$asset" -OutFile $asset
Expand-Archive -Path $asset -DestinationPath .
.\straja\straja.exe --config straja.yaml
```

## From source (Go)

```bash
make build
./bin/straja --config straja.yaml
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
  -e STRAJA_LICENSE_KEY="your-license" \
  straja:local
```

See `Dockerfile` and `Makefile` target `docker-run` for the exact runtime wiring.
