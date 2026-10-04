#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
checker="${repo_root}/scripts/check-rust-toolchain-parity.py"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/chio-rust-parity.XXXXXX")"
trap 'rm -rf "${fixture_root}"' EXIT

copy_fixture() {
  rm -rf "${fixture_root}/deploy"
  mkdir -p "${fixture_root}/deploy/docker/chio-workspace" "${fixture_root}/deploy/sidecar"
  cp "${repo_root}/Cargo.toml" "${fixture_root}/Cargo.toml"
  cp "${repo_root}/rust-toolchain.toml" "${fixture_root}/rust-toolchain.toml"
  cp "${repo_root}/deploy/docker/Dockerfile" "${fixture_root}/deploy/docker/Dockerfile"
  cp "${repo_root}/deploy/docker/Dockerfile.sidecar" "${fixture_root}/deploy/docker/Dockerfile.sidecar"
  cp "${repo_root}/deploy/docker/Dockerfile.tee" "${fixture_root}/deploy/docker/Dockerfile.tee"
  cp "${repo_root}/deploy/sidecar/Dockerfile" "${fixture_root}/deploy/sidecar/Dockerfile"
  cp "${repo_root}/deploy/docker/chio-workspace/Cargo.toml" \
    "${fixture_root}/deploy/docker/chio-workspace/Cargo.toml"
}

expect_rejection() {
  local description="$1"
  if python3 "${checker}" --repo-root "${fixture_root}" >/dev/null 2>&1; then
    echo "checker accepted ${description}" >&2
    exit 1
  fi
}

python3 "${checker}"
copy_fixture
python3 "${checker}" --repo-root "${fixture_root}"

sed -i 's/ARG RUST_VERSION=[0-9.]*/ARG RUST_VERSION=1.0.0/' \
  "${fixture_root}/deploy/docker/Dockerfile.sidecar"
expect_rejection "a stale production Rust version"

copy_fixture
sed -i '0,/rust-version = "[0-9.]*"/s//rust-version = "1.0"/' \
  "${fixture_root}/deploy/docker/chio-workspace/Cargo.toml"
expect_rejection "a stale generated workspace MSRV"

copy_fixture
sed -i '0,/@sha256:[a-f0-9]*/s//@sha256:0000000000000000000000000000000000000000000000000000000000000000/' \
  "${fixture_root}/deploy/docker/Dockerfile.sidecar"
expect_rejection "a divergent Alpine builder digest"

copy_fixture
sed -i 's/@sha256:[a-f0-9]*//' \
  "${fixture_root}/deploy/sidecar/Dockerfile"
expect_rejection "an unpinned production Rust builder"

echo "PASS: Rust toolchain parity fails closed on every production drift class"
