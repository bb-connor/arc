#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

bash scripts/check-kani-toolchain.sh

cargo kani -p chio-kernel-core --lib --default-unwind 8 --no-unwinding-checks --fail-fast

# The bounded inclusion walk is the only loop-bearing refinement harness in
# this aggregate whose sufficiency is part of its evidence claim. Re-run it
# with CBMC's unwinding assertions enabled; the aggregate above runs with
# unwinding checks off.
cargo kani -p chio-kernel-core --lib \
  --harness verify_oracle_inclusion_walk_parity --default-unwind 8

echo "Kani core harnesses passed"
