# Build stage: compile static Go binary
ARG GO_VERSION=1.24
FROM golang:${GO_VERSION}-alpine AS builder

# Build arguments
ARG VERSION=dev

# Install git for go mod (if needed for private deps)
RUN apk add --no-cache git

WORKDIR /build

# Copy go.mod and go.sum first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static binary with version injection
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o certvet \
    ./cmd/certvet

# Runtime stage: minimal distroless image
FROM gcr.io/distroless/static-debian12:nonroot

# OCI-compliant labels
LABEL org.opencontainers.image.source="https://github.com/ivoronin/certvet"
LABEL org.opencontainers.image.description="Pre-flight checks for SSL/TLS certificates against real platform trust stores"
LABEL org.opencontainers.image.licenses="ELv2"
LABEL org.opencontainers.image.title="certvet"

# Copy binary from builder
COPY --from=builder /build/certvet /certvet

# Run as non-root user (distroless:nonroot already sets this)
USER nonroot:nonroot

# Set entrypoint
ENTRYPOINT ["/certvet"]

# Default to help if no args provided
CMD ["--help"]
