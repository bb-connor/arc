#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

runner="scripts/check-consumer-boundaries.sh"
test -x "${runner}"
bash -n "${runner}"
test "$(grep -c '^  [a-z].* \\$' "${runner}")" -eq 8
test "$(grep -c '^run_case ' "${runner}")" -eq 12
grep -Fq -- '-- cargo test -p chio-conformance --test consumer_boundary --locked' "${runner}"
grep -Fq './scripts/check-protocol-peer-negotiation.sh' "${runner}"
grep -Fq './scripts/check-adapter-no-bypass.sh' "${runner}"
for workflow in .github/workflows/sdk-parity.yml .github/workflows/enterprise-hardening.yml; do
  grep -Fq './scripts/check-consumer-sdk-parity.sh' "${workflow}"
done
grep -Fq 'npm run build --workspace @chio-protocol/node-http' scripts/check-consumer-sdk-parity.sh

# The shared harness supplies behavioral missing/renamed/ignored/zero-match
# calibration. Its public peer wrapper also calibrates the single-case pattern.
bash scripts/tests/run-exact-cargo-test-inventory.test.sh
bash scripts/tests/check-protocol-peer-negotiation.test.sh
echo "Consumer boundary gate contract passed"
