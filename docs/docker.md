# Docker setup and production notes

Source: `Dockerfile`, `Makefile`

## Image behavior

- Entry point: `/app/straja --config=/etc/straja/straja.yaml`
- Exposes port `8080`
- Healthcheck: `GET http://127.0.0.1:8080/readyz`
- Runs as non-root user
- Includes ONNX Runtime shared libraries

## Expected paths inside the container

- `/etc/straja/straja.yaml` (config)
- `/var/lib/straja/intel` (intel dir)
- `/var/lib/straja/bundles` (bundle cache)

Mount these paths read-only or read-write as appropriate:

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

## Production notes

- Do not bake provider or license keys into the image; inject them via environment or a secrets manager.
- Keep `allow_private_networks: false` for providers unless you explicitly need localhost/private endpoints.
- Use `max_request_body_bytes`, `max_messages`, `max_total_message_chars`, and `max_in_flight_requests` to protect the gateway.
- Consider enabling activation sinks (`activation.*`) for auditability and `/readyz` for health monitoring.
