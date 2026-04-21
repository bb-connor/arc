# syntax=docker/dockerfile:1.7
# Multi-stage Dockerfile for arc-k8s-controller.
#
# Stage 1: build the manager binary with the module-compatible Go toolchain.
# Stage 2: ship a distroless static image running as non-root user 65532.

ARG GO_VERSION=1.22
FROM golang:${GO_VERSION} AS builder

WORKDIR /workspace

# Cache deps.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source.
COPY cmd/ cmd/
COPY internal/ internal/

# Build.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -trimpath -ldflags "-s -w" -o /out/manager ./cmd/chio-controller

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /out/manager /manager
USER 65532:65532
ENTRYPOINT ["/manager"]
