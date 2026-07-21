#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

required_executables=(
  scripts/check-enterprise-cross-mechanism.sh
  scripts/check-enterprise-test-inventories.sh
  scripts/check-exact-cargo-test-inventory.py
  scripts/check-keyring-transparency.sh
  scripts/check-protocol-primitives-concurrency.sh
  scripts/check-protocol-primitives-focused.sh
  scripts/check-secret-broker-boundary.sh
  scripts/tests/check-enterprise-gate-contracts.test.sh
  scripts/tests/check-enterprise-cross-mechanism.test.sh
  scripts/tests/check-enterprise-test-inventories.test.sh
  scripts/tests/check-exact-cargo-test-inventory.test.py
  scripts/tests/run-exact-cargo-test-inventory.test.sh
  scripts/run-exact-cargo-test-inventory.sh
  scripts/tests/check-protocol-primitives-concurrency.test.sh
  scripts/tests/check-protocol-primitives-focused.test.sh
)
for path in "${required_executables[@]}"; do
  if [[ ! -x "${path}" ]]; then
    echo "enterprise security gate is not executable: ${path}" >&2
    exit 1
  fi
done

for gate in scripts/check-keyring-transparency.sh scripts/check-secret-broker-boundary.sh; do
  if ! grep -Fq 'scripts/check-exact-cargo-test-inventory.py' "${gate}"; then
    echo "enterprise gate omits exact inventory verification: ${gate}" >&2
    exit 1
  fi
  if grep -Eq "test result: ok\\\\\. \[1-9\]\[0-9\]\* passed" "${gate}"; then
    echo "enterprise gate retains a non-exact positive-count assertion: ${gate}" >&2
    exit 1
  fi
done

assert_suppressed_trust_mismatch_fails() {
  local gate="$1"
  shift
  local output status
  set +e
  output="$(env "$@" "./${gate}" 2>&1)"
  status=$?
  set -e
  if [[ "${status}" -eq 0 ]]; then
    echo "enterprise gate accepted a suppressed trusted-path mismatch: ${gate}" >&2
    exit 1
  fi
  if [[ -z "${output}" ]]; then
    echo "enterprise gate trusted-path rejection was silent: ${gate}" >&2
    exit 1
  fi
}

assert_suppressed_trust_mismatch_fails \
  scripts/check-keyring-transparency.sh \
  CHIO_ENTERPRISE_SECURITY_RUNNER=1 \
  CHIO_SECURITY_WORKSPACE=/tmp/not-the-candidate \
  CHIO_SECURITY_EXACT_INVENTORY_CHECKER=/tmp/not-the-inventory
assert_suppressed_trust_mismatch_fails \
  scripts/check-secret-broker-boundary.sh \
  CHIO_ENTERPRISE_SECURITY_RUNNER=1 \
  CHIO_SECURITY_WORKSPACE=/tmp/not-the-candidate \
  CHIO_SECURITY_EXACT_INVENTORY_CHECKER=/tmp/not-the-inventory
assert_suppressed_trust_mismatch_fails \
  scripts/check-cage-enforcement.sh \
  CHIO_ENTERPRISE_SECURITY_RUNNER=1 \
  CHIO_SECURITY_WORKSPACE=/tmp/not-the-candidate \
  CHIO_SECURITY_LINUX_STACK_CHECKER=/tmp/not-the-stack-checker \
  CHIO_SECURITY_CAGE_INVENTORY_CHECKER=/tmp/not-the-inventory \
  CHIO_SECURITY_CAGE_LINUX_RUNNER=/tmp/not-the-runner

if ! grep -Fq './scripts/check-enterprise-cross-mechanism.sh' \
  .github/workflows/enterprise-hardening.yml; then
  echo "enterprise workflow omits the composed mechanism gate" >&2
  exit 1
fi
echo "enterprise gate static contracts passed"
