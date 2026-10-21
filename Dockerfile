# Build stage
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

# Retain git for Go module downloads that need a direct VCS fallback. Build
# identity is supplied explicitly; this context contains only the node module.
RUN apk add --no-cache git

WORKDIR /build

COPY go.mod go.sum ./
# Local protocol patches must be present when Go resolves module replacements.
COPY internal/deps ./internal/deps
RUN go mod download

COPY . .

ARG VERSION=dev
ARG BUILD_TIME=unknown
ARG COMMIT=unknown
ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags "-s -w \
    -X github.com/ANRCM0/TX-Node/internal/buildinfo.Version=${VERSION} \
    -X github.com/ANRCM0/TX-Node/internal/buildinfo.BuildTime=${BUILD_TIME} \
    -X github.com/ANRCM0/TX-Node/internal/buildinfo.Commit=${COMMIT}" \
    -o tx-node ./cmd/tx-node

# Runtime stage — the native txnode data plane is compiled in
FROM alpine:3.20

ARG VERSION=dev
ARG BUILD_TIME=unknown
ARG COMMIT=unknown
ARG SOURCE_URL=https://github.com/ANRCM0/txnode
LABEL org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_TIME}"

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /build/tx-node /usr/local/bin/tx-node

# /etc/txnode is the canonical container config root. Keep the legacy
# directory only for the bounded old-Compose bind-mount compatibility window.
RUN mkdir -p /etc/txnode /etc/xboard-node

WORKDIR /etc/txnode

# Config can be provided via file mount OR environment variables.
# Environment-variable bootstrap retains Xboard-compatible defaults. To use
# TXBoard native node/v1 or Machine mode, mount a YAML config with
# panel.provider: txboard (and machine.machine_id/token when applicable).
# Env var mode (no config file needed):
#   docker run -d --network=host \
#     -e apiHost=https://panel.example.com \
#     -e apiKey=YOUR_TOKEN \
#     -e nodeID=1 \
#     ghcr.io/anrcm0/txboard-node:latest
#
# Supported env vars:
#   apiHost  / API_HOST    → panel URL
#   apiKey   / API_KEY     → server token
#   nodeID   / NODE_ID     → node ID
#   nodeType / NODE_TYPE   → node type (optional)
#   kernel   / KERNEL_TYPE → txnode (only supported value)
#   domain   / DOMAIN      → TLS domain (enables auto_tls)
#   certFile / CERT_FILE   → TLS cert path
#   keyFile  / KEY_FILE    → TLS key path
#   logLevel / LOG_LEVEL   → log level

ENTRYPOINT ["tx-node"]
CMD ["-c", "/etc/txnode/config.yml"]
