# syntax=docker/dockerfile:1

ARG GO_VERSION=1.25.4
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Build dependencies for StrajaGuard + healthcheck helper
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl build-essential pkg-config busybox-static && \
    rm -rf /var/lib/apt/lists/*

# Install ONNX Runtime from upstream release (arch-specific)
ARG ORT_VERSION=1.22.0
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) ORT_ARCH=x64 ;; \
      arm64) ORT_ARCH=aarch64 ;; \
      *) echo "unsupported arch ${TARGETARCH}" && exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/onnxruntime-linux-${ORT_ARCH}-${ORT_VERSION}.tgz" -o /tmp/ort.tgz && \
    mkdir -p /tmp/ort && tar -xzf /tmp/ort.tgz -C /tmp/ort --strip-components=1 && \
    cp -r /tmp/ort/include/* /usr/local/include/ && \
    cp -r /tmp/ort/lib/* /usr/local/lib/ && \
    echo "/usr/local/lib" > /etc/ld.so.conf.d/onnxruntime.conf && ldconfig && \
    rm -rf /tmp/ort /tmp/ort.tgz

# Go module download first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build Straja (CGO-enabled for ONNX Runtime)
RUN CGO_ENABLED=1 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/straja ./cmd/straja

# Capture runtime deps (full ORT libs + stdlib + busybox for healthcheck)
RUN mkdir -p /out/lib && \
    cp /usr/local/lib/libonnxruntime* /out/lib/ && \
    cp /usr/lib/*-linux-gnu/libgomp.so.1 /out/lib/ && \
    cp /usr/lib/*-linux-gnu/libstdc++.so.6 /out/lib/ && \
    cp /usr/lib/*-linux-gnu/libgcc_s.so.1 /out/lib/ && \
    for f in /out/lib/libonnxruntime.so.*; do ln -sf "$(basename "$f")" /out/lib/libonnxruntime.so; done && \
    cp /bin/busybox /out/busybox && \
    mkdir -p /out/etc/straja /out/var/lib/straja/intel /out/var/lib/straja/bundles && \
    chown -R 65532:65532 /out/etc /out/var

# =========================
# Runtime image
# =========================
FROM gcr.io/distroless/base-debian12

WORKDIR /app

COPY --from=builder /src/straja.yaml /etc/straja/straja.yaml
COPY --from=builder /out/straja /app/straja
COPY --from=builder /out/lib/ /usr/local/lib/
COPY --from=builder /out/lib/ /usr/lib/
COPY --from=builder /out/busybox /busybox
COPY --from=builder /out/etc /etc
COPY --from=builder /out/var /var

ENV ONNXRUNTIME_SHARED_LIBRARY_PATH=/usr/local/lib/libonnxruntime.so \
    LD_LIBRARY_PATH=/usr/local/lib:/usr/lib

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/busybox","wget","-qO-","http://127.0.0.1:8080/readyz"]

USER nonroot

ENTRYPOINT ["/app/straja"]
CMD ["--config=/etc/straja/straja.yaml"]
