# =========================
# 1) Builder image
# =========================
FROM golang:1.25-bookworm AS builder

WORKDIR /app

# Install build dependencies (gcc for CGO + onnxruntime headers/runtime)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git build-essential pkg-config onnxruntime && \
    rm -rf /var/lib/apt/lists/*

# Go module files first (better layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build Straja (CGO-enabled for ONNX Runtime)
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o /app/straja ./cmd/straja

# =========================
# 2) Runtime image
# =========================
FROM debian:bookworm-slim

# Install ONNX Runtime shared library for StrajaGuard ML
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates onnxruntime && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user and writable runtime dirs
RUN useradd -m -s /bin/bash straja && \
    mkdir -p /app/intel/strajaguard_v1 && \
    chown -R straja:straja /app

USER straja
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/straja /app/straja

# Expose default HTTP port (matches server.addr :8080)
EXPOSE 8080

# Default entrypoint: run straja
ENTRYPOINT ["/app/straja"]

# Default command: use config at /app/straja.yaml
CMD ["--config=/app/straja.yaml"]
