#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

./scripts/check-release-inputs.sh
./scripts/check-workspace-layering.sh
./scripts/check-formal-proofs.sh
./scripts/check-aeneas-pilot.sh
./scripts/check-aeneas-production.sh
./scripts/check-aeneas-equivalence.sh
./scripts/check-rust-verification-gates.sh
./scripts/check-adapter-no-bypass.sh
./scripts/check-portable-kernel.sh
if [[ "${CHIO_STRICT_RUST_VERIFICATION:-0}" == "1" ]]; then
  ./scripts/generate-proof-report.sh
  ./scripts/check-proof-report.sh
else
  echo "Skipping proof report generation until strict Rust verification tools are enabled"
fi
cargo fmt --all -- --check
# Keep the CI warning gate focused on repo-shipping targets; test/bench-only
# lint backlogs are exercised by `cargo test` and can be migrated separately.
cargo clippy --workspace --lib --bins --examples -- -D warnings
cargo build --workspace
# `chio-wasm-guards` pulls in large wasmtime-backed integration binaries when
# features unify across the workspace, which has been tripping the Linux CI
# linker. Keep the default lane on the full workspace minus that package and
# run its lighter library tests separately.
cargo test --workspace --exclude chio-wasm-guards
cargo test -p chio-wasm-guards --lib
