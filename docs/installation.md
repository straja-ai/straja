# Installation

## Binary (recommended)

```bash
curl -LO https://github.com/straja-ai/straja/releases/latest/download/straja
chmod +x straja
```

Run with:

```bash
./straja --config straja.yaml
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
