#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

./scripts/check-release-inputs.sh
./scripts/check-workspace-layering.sh
./scripts/check-formal-proofs.sh
cargo fmt --all -- --check
# Keep the CI warning gate focused on repo-shipping targets; test/bench-only
# lint backlogs are exercised by `cargo test` and can be migrated separately.
cargo clippy --workspace --lib --bins --examples -- -D warnings
cargo build --workspace
cargo test --workspace
