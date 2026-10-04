#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# A path dependency is not identified by Cargo Vet's registry audit. Require
# the independently reviewed fork, its authenticated reconstruction and every
# deployment resolution before accepting the registry/transitive audit graph.
python3 scripts/tests/check-aws-lc-fork.test.py
python3 scripts/check-aws-lc-fork.py "$@"
cargo vet --locked
cargo test --locked --manifest-path third_party/aws-lc-rs-chio/Cargo.toml \
  --features legacy-des --test des_parity_regression
cargo test --locked --manifest-path third_party/aws-lc-rs-chio/Cargo.toml \
  --lib cipher::key::tests::aes_schedules_initialize_unused_words -- --exact
