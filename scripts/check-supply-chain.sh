#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# The fork is an audited source tree, so build products must live outside it.
# Keep an explicitly supplied target directory for existing qualification lanes.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${PWD}/target/aws-lc-audit}"

# A path dependency is not identified by Cargo Vet's registry audit. Require
# the independently reviewed fork, its authenticated reconstruction and every
# deployment resolution before accepting the registry/transitive audit graph.
python3 scripts/tests/check-supply-chain-workflows.test.py
python3 scripts/tests/render-vcpkg-release.test.py
python3 scripts/tests/check-aws-lc-fork.test.py
python3 scripts/tests/check-aws-lc-lints.test.py
python3 scripts/check-aws-lc-fork.py "$@"
python3 scripts/check-aws-lc-lints.py
cargo vet --locked
cargo test --locked --manifest-path third_party/aws-lc-rs-chio/Cargo.toml \
  --features legacy-des --test des_parity_regression
cargo test --locked --manifest-path third_party/aws-lc-rs-chio/Cargo.toml \
  --lib cipher::key::tests::aes_schedules_initialize_unused_words -- --exact
cargo test --locked --manifest-path third_party/aws-lc-rs-chio/Cargo.toml \
  --lib --no-default-features --features alloc,fips,ring-io,ring-sig-verify \
  rsa::key::fips_validation_tests::non_rsa_key_is_rejected_without_panicking -- --exact
