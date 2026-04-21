# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.93
ARG ALPINE_VERSION=3.22
ARG NODE_VERSION=22

FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS rust-builder
RUN apk add --no-cache build-base cmake perl pkgconf
WORKDIR /workspace

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY examples/hello-tool ./examples/hello-tool
COPY formal/diff-tests ./formal/diff-tests
COPY tests/e2e ./tests/e2e

RUN cargo build --locked -p chio-cli --bin chio

FROM node:${NODE_VERSION}-alpine AS dashboard-builder
WORKDIR /workspace/crates/chio-cli/dashboard

COPY crates/chio-cli/dashboard/package.json ./
COPY crates/chio-cli/dashboard/package-lock.json ./
RUN npm ci --no-fund --no-audit

COPY crates/chio-cli/dashboard/index.html ./
COPY crates/chio-cli/dashboard/tsconfig.json ./
COPY crates/chio-cli/dashboard/tsconfig.app.json ./
COPY crates/chio-cli/dashboard/vite.config.ts ./
COPY crates/chio-cli/dashboard/src ./src

RUN npm run build

FROM alpine:${ALPINE_VERSION} AS chio
RUN apk add --no-cache ca-certificates libgcc libstdc++
COPY --from=rust-builder /workspace/target/debug/chio /usr/local/bin/chio
ENTRYPOINT ["chio"]
CMD ["--help"]

FROM chio AS chio-trust-demo
WORKDIR /opt/chio
COPY --from=dashboard-builder /workspace/crates/chio-cli/dashboard/dist ./dashboard/dist
EXPOSE 8940
ENTRYPOINT []
CMD ["/bin/sh", "-lc", "exec /usr/local/bin/chio --receipt-db /var/lib/chio/receipts.sqlite --revocation-db /var/lib/chio/revocations.sqlite --authority-db /var/lib/chio/authority.sqlite --budget-db /var/lib/chio/budgets.sqlite trust serve --listen 0.0.0.0:8940 --service-token \"${CHIO_SERVICE_TOKEN:-demo-token}\""]

FROM chio AS chio-mcp-demo
RUN apk add --no-cache python3
WORKDIR /opt/chio
COPY examples/docker/mock_mcp_server.py ./examples/mock_mcp_server.py
COPY examples/docker/policy.yaml ./examples/policy.yaml
EXPOSE 8931
ENTRYPOINT []
CMD ["/bin/sh", "-lc", "exec /usr/local/bin/chio --control-url \"${CHIO_CONTROL_URL:-http://chio-trust-demo:8940}\" --control-token \"${CHIO_CONTROL_TOKEN:-demo-token}\" mcp serve-http --policy /opt/chio/examples/policy.yaml --server-id wrapped-http-mock --server-name \"Wrapped HTTP Mock\" --listen 0.0.0.0:8931 --auth-token \"${CHIO_AUTH_TOKEN:-demo-token}\" -- python3 /opt/chio/examples/mock_mcp_server.py"]
