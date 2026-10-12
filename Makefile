VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
SOURCE_URL ?= https://github.com/ANRCM0/TXBoard
LDFLAGS := -s -w -X github.com/ANRCM0/TX-Node/internal/buildinfo.Version=$(VERSION) -X github.com/ANRCM0/TX-Node/internal/buildinfo.BuildTime=$(BUILD_TIME) -X github.com/ANRCM0/TX-Node/internal/buildinfo.Commit=$(COMMIT)

.PHONY: build clean test test-runtime-stability docker build-linux build-linux-arm64 build-all

# Build for current platform
build:
	go build -ldflags "$(LDFLAGS)" -tags "with_quic with_utls with_wireguard with_clash_api" -o tx-node ./cmd/tx-node

# Build for Linux amd64
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -tags "with_quic with_utls with_wireguard with_acme with_clash_api" -o tx-node-linux-amd64 ./cmd/tx-node

# Build for Linux arm64
build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -tags "with_quic with_utls with_wireguard with_acme with_clash_api" -o tx-node-linux-arm64 ./cmd/tx-node

# Build all platforms
build-all: build-linux build-linux-arm64

# Run tests
test:
	go test -v -race -count=1 ./internal/...
	go test ./cmd/tx-node

# Re-run the extracted runtime-controller suites under the race detector with
# randomized test order. This is intentionally focused: it guards the lifecycle
# boundaries introduced by Runtime Simplification S1-S3 without multiplying the
# cost of every kernel/protocol test.
test-runtime-stability:
	go test -race -shuffle=on -count=10 -timeout=5m \
		./internal/nodesync \
		./internal/pushsync \
		./internal/reporting \
		./internal/userstate \
		./internal/kernellifecycle \
		./internal/certcoord \
		./internal/auditcoord \
		./internal/geoassets

# Clean build artifacts
clean:
	rm -f tx-node tx-node-linux-*

# Build Docker image
docker:
	docker build --build-arg VERSION="$(VERSION)" --build-arg COMMIT="$(COMMIT)" --build-arg BUILD_TIME="$(BUILD_TIME)" --build-arg SOURCE_URL="$(SOURCE_URL)" -t txboard-node:$(VERSION) -t txboard-node:latest .
