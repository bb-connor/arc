#!/usr/bin/env bash
set -euo pipefail
cd /home/connor/backbay/arc-funded-integration
umask 022
ulimit -c 0
export CARGO_BUILD_JOBS=3 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_NET_OFFLINE=true RUST_TEST_THREADS=1
EVIDENCE=/home/connor/backbay/chio-funded-integration-evidence
bash "$EVIDENCE/caller-custody-inventory.sh" > "$EVIDENCE/caller-custody-inventory.log" 2>&1
./scripts/check-authenticated-caller-delivery.sh > "$EVIDENCE/caller-custody-authenticated.log" 2>&1
./scripts/run-exact-cargo-test-inventory.sh --label "original physical DPoP caller custody" --allow-filtered --expected \
  admission_operation_store::tests::dpop_replay::claims::kernel_routes::authenticated_caller::authenticated_caller_start_retains_physical_dpop_and_reports_after_proof_expiry \
  -- cargo test -p chio-store-sqlite --lib --locked authenticated_caller_start_retains_physical_dpop_and_reports_after_proof_expiry > "$EVIDENCE/caller-custody-physical-dpop.log" 2>&1
cargo check --workspace --all-targets --locked --offline > "$EVIDENCE/caller-custody-workspace-check.log" 2>&1
cargo clippy --workspace --all-targets --locked --offline -- -D warnings > "$EVIDENCE/caller-custody-workspace-clippy.log" 2>&1
printf 'Caller custody qualification passed\n'
