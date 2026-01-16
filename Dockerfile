# Build stage
FROM golang:1.21-alpine AS builder

ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev

WORKDIR /build

# Copy go mod files (go.sum helps with reproducible builds)
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source
COPY main.go .

# Copy config file
COPY config/config.json /build/config/config.json

# Map TARGETARCH to GOARCH and set GOARM for arm/v7
# TARGETARCH: amd64, arm64, arm
# TARGETVARIANT: v7 (for arm/v7)
RUN set -e; \
    case ${TARGETARCH} in \
        amd64) \
            CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
                -ldflags="-w -s -X main.version=${VERSION}" \
                -o cert-watcher \
                main.go ;; \
        arm64) \
            CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
                -ldflags="-w -s -X main.version=${VERSION}" \
                -o cert-watcher \
                main.go ;; \
        arm) \
            if [ "${TARGETVARIANT}" = "v7" ]; then \
                CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build \
                    -ldflags="-w -s -X main.version=${VERSION}" \
                    -o cert-watcher \
                    main.go; \
            else \
                CGO_ENABLED=0 GOOS=linux GOARCH=arm go build \
                    -ldflags="-w -s -X main.version=${VERSION}" \
                    -o cert-watcher \
                    main.go; \
            fi ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" && exit 1 ;; \
    esac

# Final stage - scratch
FROM scratch

# Copy binary
COPY --from=builder /build/cert-watcher /cert-watcher

# Copy embedded config file
COPY --from=builder /build/config/config.json /config/config.json

# Note: USER directive not supported in scratch images
# Set user via docker-compose or runtime configuration

# Use embedded config file by default, but allow override via command line
ENTRYPOINT ["/cert-watcher"]
CMD ["--config", "/config/config.json"]