# syntax=docker/dockerfile:1.7
#
# ARC sidecar image.
#
# Build:
#   docker build -f deploy/sidecar/Dockerfile -t ghcr.io/backbay/arc-sidecar:latest .
#
# The sidecar exposes :9090 and responds to GET /health. It reads policy and
# signing material from env vars documented in
# docs/protocols/CLOUD-SIDECAR-INTEGRATION.md; if ARC_KERNEL_CONFIG_PATH is
# unreadable the process exits non-zero and the platform marks the container
# unhealthy (fail closed).

ARG RUST_VERSION=1.93
ARG DEBIAN_VERSION=bookworm

# -----------------------------------------------------------------------------
# Stage 1: build the arc-sidecar binary.
# -----------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS builder

ENV CARGO_TERM_COLOR=always \
    CARGO_NET_RETRY=5 \
    RUSTFLAGS="-C strip=symbols"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        libssl-dev \
        pkg-config \
        perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY examples ./examples
COPY formal ./formal
COPY tests ./tests

# The sidecar binary lives in arc-cli (arc serve-sidecar). If a dedicated
# arc-sidecar bin is introduced, replace the --bin arg accordingly.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked -p arc-cli --bin arc \
 && mkdir -p /out \
 && cp /build/target/release/arc /out/arc-sidecar

# -----------------------------------------------------------------------------
# Stage 2: healthcheck helper (distroless has no shell or curl).
# We bake a tiny statically linked HTTP probe in a throwaway stage.
# -----------------------------------------------------------------------------
FROM debian:${DEBIAN_VERSION}-slim AS healthcheck
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# Stage 3: runtime image. Distroless cc-debian12 nonroot (uid 65532).
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# Metadata.
LABEL org.opencontainers.image.title="arc-sidecar" \
      org.opencontainers.image.description="ARC (Chio) kernel sidecar for multi-container platforms" \
      org.opencontainers.image.source="https://github.com/backbay/arc" \
      org.opencontainers.image.licenses="Apache-2.0"

# Runtime config defaults (overridable at deploy time).
ENV ARC_LISTEN_ADDR=0.0.0.0:9090 \
    ARC_HEALTH_PATH=/health \
    ARC_LOG_LEVEL=info \
    ARC_KERNEL_CONFIG_PATH=/etc/arc/kernel.yaml

# Copy the binary and the healthcheck helper from earlier stages.
COPY --from=builder /out/arc-sidecar /usr/local/bin/arc-sidecar
COPY --from=healthcheck /usr/bin/curl /usr/bin/curl
COPY --from=healthcheck /usr/lib/x86_64-linux-gnu/libcurl.so.4 /usr/lib/x86_64-linux-gnu/libcurl.so.4
COPY --from=healthcheck /usr/lib/x86_64-linux-gnu/libnghttp2.so.14 /usr/lib/x86_64-linux-gnu/libnghttp2.so.14
COPY --from=healthcheck /usr/lib/x86_64-linux-gnu/libidn2.so.0 /usr/lib/x86_64-linux-gnu/libidn2.so.0
COPY --from=healthcheck /usr/lib/x86_64-linux-gnu/librtmp.so.1 /usr/lib/x86_64-linux-gnu/librtmp.so.1
COPY --from=healthcheck /usr/lib/x86_64-linux-gnu/libssh2.so.1 /usr/lib/x86_64-linux-gnu/libssh2.so.1
COPY --from=healthcheck /usr/lib/x86_64-linux-gnu/libpsl.so.5 /usr/lib/x86_64-linux-gnu/libpsl.so.5
COPY --from=healthcheck /usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2 /usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2
COPY --from=healthcheck /usr/lib/x86_64-linux-gnu/libldap-2.5.so.0 /usr/lib/x86_64-linux-gnu/libldap-2.5.so.0
COPY --from=healthcheck /usr/lib/x86_64-linux-gnu/liblber-2.5.so.0 /usr/lib/x86_64-linux-gnu/liblber-2.5.so.0
COPY --from=healthcheck /usr/lib/x86_64-linux-gnu/libzstd.so.1 /usr/lib/x86_64-linux-gnu/libzstd.so.1
COPY --from=healthcheck /usr/lib/x86_64-linux-gnu/libbrotlidec.so.1 /usr/lib/x86_64-linux-gnu/libbrotlidec.so.1
COPY --from=healthcheck /usr/lib/x86_64-linux-gnu/libbrotlicommon.so.1 /usr/lib/x86_64-linux-gnu/libbrotlicommon.so.1

# Nonroot (uid/gid 65532) is already the default user in distroless:nonroot;
# make it explicit so manifests that introspect the image know.
USER 65532:65532

EXPOSE 9090

# Fail closed: if the health endpoint is not reachable the platform recycles
# the container. The probe uses the baked-in curl binary to hit localhost.
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/bin/curl", "-fsS", "http://localhost:9090/health"]

ENTRYPOINT ["/usr/local/bin/arc-sidecar"]
CMD ["serve-sidecar", "--listen", "0.0.0.0:9090"]
