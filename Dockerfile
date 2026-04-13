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

RUN cargo build --locked -p arc-cli --bin arc

FROM node:${NODE_VERSION}-alpine AS dashboard-builder
WORKDIR /workspace/crates/arc-cli/dashboard

COPY crates/arc-cli/dashboard/package.json ./
COPY crates/arc-cli/dashboard/package-lock.json ./
RUN npm ci --no-fund --no-audit

COPY crates/arc-cli/dashboard/index.html ./
COPY crates/arc-cli/dashboard/tsconfig.json ./
COPY crates/arc-cli/dashboard/tsconfig.app.json ./
COPY crates/arc-cli/dashboard/vite.config.ts ./
COPY crates/arc-cli/dashboard/src ./src

RUN npm run build

FROM alpine:${ALPINE_VERSION} AS arc
RUN apk add --no-cache ca-certificates libgcc libstdc++
COPY --from=rust-builder /workspace/target/debug/arc /usr/local/bin/arc
ENTRYPOINT ["arc"]
CMD ["--help"]

FROM arc AS arc-trust-demo
WORKDIR /opt/arc
COPY --from=dashboard-builder /workspace/crates/arc-cli/dashboard/dist ./dashboard/dist
EXPOSE 8940
ENTRYPOINT []
CMD ["/bin/sh", "-lc", "exec /usr/local/bin/arc --receipt-db /var/lib/arc/receipts.sqlite --revocation-db /var/lib/arc/revocations.sqlite --authority-db /var/lib/arc/authority.sqlite --budget-db /var/lib/arc/budgets.sqlite trust serve --listen 0.0.0.0:8940 --service-token \"${ARC_SERVICE_TOKEN:-demo-token}\""]

FROM arc AS arc-mcp-demo
RUN apk add --no-cache python3
WORKDIR /opt/arc
COPY examples/docker/mock_mcp_server.py ./examples/mock_mcp_server.py
COPY examples/docker/policy.yaml ./examples/policy.yaml
EXPOSE 8931
ENTRYPOINT []
CMD ["/bin/sh", "-lc", "exec /usr/local/bin/arc --control-url \"${ARC_CONTROL_URL:-http://arc-trust-demo:8940}\" --control-token \"${ARC_CONTROL_TOKEN:-demo-token}\" mcp serve-http --policy /opt/arc/examples/policy.yaml --server-id wrapped-http-mock --server-name \"Wrapped HTTP Mock\" --listen 0.0.0.0:8931 --auth-token \"${ARC_AUTH_TOKEN:-demo-token}\" -- python3 /opt/arc/examples/mock_mcp_server.py"]
