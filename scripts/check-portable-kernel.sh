#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/portable-kernel}"

rustup target add wasm32-unknown-unknown >/dev/null

echo "[portable-kernel] building host target with --no-default-features"
cargo build -p arc-kernel-core --no-default-features

echo "[portable-kernel] building wasm32-unknown-unknown with --no-default-features"
cargo build -p arc-kernel-core --target wasm32-unknown-unknown --no-default-features

echo "[portable-kernel] ok"
