# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.95.0
ARG DEBIAN_VERSION=bookworm

FROM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION}@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake libssl-dev pkg-config perl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY crates ./crates
COPY third_party ./third_party
COPY bench ./bench
COPY contracts ./contracts
COPY spec ./spec
COPY fixtures ./fixtures
COPY formal ./formal
COPY tests ./tests
COPY wit ./wit
COPY examples ./examples
COPY integrations ./integrations
COPY sdks ./sdks
COPY xtask ./xtask
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --locked --profile docker-release --jobs 1 \
      -p chio-finding-market-server --bin chio-finding-market-server \
      -p chio-finding-market-migrator --bin chio-finding-market-migrate \
    && install -D -m 0755 target/docker-release/chio-finding-market-server /out/chio-finding-market-server \
    && install -D -m 0755 target/docker-release/chio-finding-market-migrate /out/chio-finding-market-migrate

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime
COPY --from=builder /out/chio-finding-market-server /usr/local/bin/chio-finding-market-server
COPY --from=builder /out/chio-finding-market-migrate /usr/local/bin/chio-finding-market-migrate
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/chio-finding-market-server"]
CMD ["--help"]
