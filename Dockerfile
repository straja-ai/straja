# =========================
# 1) Builder image
# =========================
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies (if needed later)
RUN apk add --no-cache git

# Go module files first (better layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build Straja (static-ish binary, linux/amd64)
RUN CGO_DISABLED=1 GOOS=linux GOARCH=amd64 go build -o /app/straja ./cmd/straja

# =========================
# 2) Runtime image
# =========================
FROM alpine:3.20

# Create non-root user
RUN adduser -D -g '' straja

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