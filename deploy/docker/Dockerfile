# syntax=docker/dockerfile:1.7
# Chio CLI image. Builds the `chio` binary plus the optional trust/MCP demo
# stages. Base images are digest-pinned to match Dockerfile.sidecar /
# Dockerfile.tee; bump the digests in lockstep with those files.

ARG RUST_VERSION=1.94.1
ARG ALPINE_VERSION=3.22
ARG NODE_VERSION=22

FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION}@sha256:797631f9efd6957d0013f200e410478c380907eee3b469c6f80d89022df28bc7 AS rust-builder
RUN apk add --no-cache build-base cmake openssl-dev openssl-libs-static pkgconf
# The musl target links statically, so OpenSSL must be the static archive.
ENV OPENSSL_STATIC=1 \
    OPENSSL_NO_VENDOR=1 \
    PKG_CONFIG_ALL_STATIC=1
WORKDIR /workspace

COPY deploy/docker/chio-workspace/Cargo.toml ./Cargo.toml
COPY deploy/docker/chio-workspace/Cargo.lock ./Cargo.lock
COPY .cargo ./.cargo
COPY crates ./crates
COPY third_party ./third_party
COPY examples/chio-3vendor/fixtures/runtime-spine/scenario.json ./examples/chio-3vendor/fixtures/runtime-spine/scenario.json
COPY fixtures/proof-room ./fixtures/proof-room
COPY spec ./spec
COPY wit ./wit
# The trace validator and the conformance runner embed TLA models and
# fixtures from this tree at compile time.
COPY formal/tla ./formal/tla

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/workspace/target,sharing=locked \
    cargo metadata --format-version 1 --locked >/dev/null \
 && cargo build --profile docker-release --locked -p chio-cli --bin chio \
 && cp target/docker-release/chio /chio

FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION}@sha256:797631f9efd6957d0013f200e410478c380907eee3b469c6f80d89022df28bc7 AS proof-room-builder
WORKDIR /workspace

# The proof room builds from the repository workspace. Cargo loads every
# member manifest before it builds one package, so each workspace member root
# is copied along with the schemas and fixtures the build reads at compile time.
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY crates ./crates
COPY third_party ./third_party
COPY bench ./bench
COPY examples ./examples
COPY formal ./formal
COPY integrations ./integrations
COPY tests ./tests
COPY xtask ./xtask
COPY spec ./spec
COPY fixtures/proof-room ./fixtures/proof-room

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/workspace/target,sharing=locked \
    cargo metadata --format-version 1 --locked >/dev/null \
 && cargo build --release --locked -p chio-proof-room --bin chio-proof-room \
 && cp target/release/chio-proof-room /chio-proof-room

FROM node:${NODE_VERSION}-alpine@sha256:968df39aedcea65eeb078fb336ed7191baf48f972b4479711397108be0966920 AS dashboard-builder
WORKDIR /workspace/crates/products/chio-cli/dashboard

COPY crates/products/chio-cli/dashboard/package.json ./
COPY crates/products/chio-cli/dashboard/package-lock.json ./
RUN npm ci --no-fund --no-audit

COPY crates/products/chio-cli/dashboard/index.html ./
COPY crates/products/chio-cli/dashboard/tsconfig.json ./
COPY crates/products/chio-cli/dashboard/tsconfig.app.json ./
COPY crates/products/chio-cli/dashboard/vite.config.ts ./
COPY crates/products/chio-cli/dashboard/src ./src

RUN npm run build

FROM alpine:${ALPINE_VERSION}@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601 AS chio
# `tini` is PID 1 so the kernel reaps zombies and forwards signals; the demo
# stages below run their real command via `exec` so signals reach it directly.
# A dedicated non-root `chio` user (UID/GID 10001, matching the sidecar/TEE
# images) owns the runtime state directories so nothing runs as root.
RUN apk add --no-cache ca-certificates libgcc libstdc++ tini \
 && addgroup -S -g 10001 chio \
 && adduser  -S -u 10001 -G chio -h /home/chio -s /sbin/nologin chio \
 && mkdir -p /var/lib/chio /opt/chio \
 && chown -R chio:chio /var/lib/chio /opt/chio /home/chio
COPY --from=rust-builder /chio /usr/local/bin/chio
RUN chmod 0755 /usr/local/bin/chio

LABEL org.opencontainers.image.title="chio" \
      org.opencontainers.image.description="Chio capability kernel CLI" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/backbay-labs/chio"

USER chio:chio
ENTRYPOINT ["/sbin/tini", "--", "chio"]
CMD ["--help"]

FROM chio AS chio-trust-demo
WORKDIR /opt/chio
COPY --from=dashboard-builder --chown=chio:chio /workspace/crates/products/chio-cli/dashboard/dist ./dashboard/dist
EXPOSE 8940
ENTRYPOINT []
CMD ["/bin/sh", "-lc", "exec /sbin/tini -- /usr/local/bin/chio --receipt-db /var/lib/chio/receipts.sqlite --authority-db /var/lib/chio/authority.sqlite --session-db /var/lib/chio/trust-sessions.sqlite trust serve --listen 0.0.0.0:8940 --service-token \"${CHIO_SERVICE_TOKEN:-demo-control-token}\" --authority-workload-token \"${CHIO_AUTHORITY_WORKLOAD_TOKEN:-demo-workload-token}\""]

FROM chio AS chio-mcp-demo
USER root
RUN apk add --no-cache python3
WORKDIR /opt/chio
COPY --chown=chio:chio examples/docker/mock_mcp_server.py ./examples/mock_mcp_server.py
COPY --chown=chio:chio examples/docker/policy.yaml ./examples/policy.yaml
COPY --chown=root:root --chmod=0555 examples/docker/mcp_demo_entrypoint.py ./examples/mcp_demo_entrypoint.py
USER chio:chio
EXPOSE 8931
# The entrypoint requires three distinct bearer credentials in the environment
# and passes them to the edge without exposing them on argv.
ENTRYPOINT ["/opt/chio/examples/mcp_demo_entrypoint.py"]

FROM alpine:${ALPINE_VERSION}@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601 AS chio-proof-room-quickstart
WORKDIR /opt/chio
RUN apk add --no-cache ca-certificates tini \
 && addgroup -S -g 10001 chio \
 && adduser  -S -u 10001 -G chio -h /home/chio -s /sbin/nologin chio \
 && mkdir -p /opt/chio /home/chio \
 && chown -R chio:chio /opt/chio /home/chio
COPY --from=proof-room-builder /chio-proof-room /usr/local/bin/chio-proof-room
RUN chmod 0755 /usr/local/bin/chio-proof-room
COPY --from=dashboard-builder --chown=chio:chio /workspace/crates/products/chio-cli/dashboard/dist ./dashboard/dist
COPY --chown=chio:chio fixtures/proof-room ./fixtures/proof-room
ENV CHIO_PROOF_ROOM_UI_DIR=/opt/chio/dashboard/dist
ENV CHIO_PROOF_FIXTURE_ROOT=/opt/chio/fixtures/proof-room
ENV CHIO_PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS=31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc,e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa
ENV CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS=ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a
ENV CHIO_TRANSACTION_TRUSTED_ROOT_KEYS=ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,68f4b6017d0f876a55c80a82b8388a54aad264d367269e2de8be079c935b5f96
ENV CHIO_SWARM_TRUSTED_WITNESS_KEYS=43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de
ENV CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS=e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa
ENV CHIO_DISCLOSURE_TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_KEYS=e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa
EXPOSE 7391
USER chio:chio
ENTRYPOINT []
CMD ["/sbin/tini", "--", "/usr/local/bin/chio-proof-room", "--bundle", "/opt/chio/fixtures/proof-room/first-run/single-call-authority/proof-room-bundle", "--ui-dir", "/opt/chio/dashboard/dist", "--fixture-root", "/opt/chio/fixtures/proof-room", "--listen", "0.0.0.0:7391", "--doctor-report", "/opt/chio/proof-doctor-report.json"]
