#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

./scripts/run-exact-cargo-test-inventory.sh \
  --label "enterprise cross-mechanism composition" \
  --expected enterprise_invocation_composes_all_controls_and_mutations_fail_closed -- \
  cargo test -p chio-conformance --features enterprise-native \
    --test enterprise_cross_mechanism

echo "Enterprise cross-mechanism gate passed (1 exact test)"
