#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo build --workspace
cargo test --workspace
