#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT

mkdir -p "${fixture}"/{crates,spec,sdks,scripts,docs,formal,xtask}
cp "${root}/scripts/check-chio-owned-v1-only.sh" "${fixture}/scripts/"

printf '%s\n' \
  'const SCHEMA: &str = "chio.cage-migration-posture.v2";' \
  > "${fixture}/crates/independent-security.rs"
printf 'struct ChioSignedBrokerExecutionReceipt%s; const ChioBrokerExecutionReceipt%s: &str = "broker";\n' 'V2' 'V2' \
  >> "${fixture}/crates/independent-security.rs"
bash "${fixture}/scripts/check-chio-owned-v1-only.sh" >/dev/null

printf 'struct CapabilityToken%s;\n' 'V2' > "${fixture}/crates/core-capability.rs"
if bash "${fixture}/scripts/check-chio-owned-v1-only.sh" >/dev/null 2>&1; then
  echo "future capability token unexpectedly passed the core v1 gate" >&2
  exit 1
fi

rm "${fixture}/crates/core-capability.rs"
printf 'struct ChioSignedBrokerExecutionReceipt%s; struct Receipt%s;\n' 'V2' 'V2' \
  > "${fixture}/crates/core-receipt.rs"
if bash "${fixture}/scripts/check-chio-owned-v1-only.sh" >/dev/null 2>&1; then
  echo "a broker envelope hid a future core receipt on the same line" >&2
  exit 1
fi
printf 'const PATH: &str = "receipt/%s.schema.json";\n' 'v2' \
  > "${fixture}/crates/core-receipt.rs"
if bash "${fixture}/scripts/check-chio-owned-v1-only.sh" >/dev/null 2>&1; then
  echo "future receipt schema unexpectedly passed the core v1 gate" >&2
  exit 1
fi


# Internal App metadata v2 is confined to its reviewed exact producers and validators.
rm "${fixture}/crates/core-receipt.rs"
mkdir -p "${fixture}/scripts/tests"
authority_paths=(
  scripts/audit-security-merge-qualification.py
  scripts/check-security-ci-contract.py
  scripts/tests/trusted-ci-landing-regressions.test.py
  scripts/tests/trusted-main-codegen-regressions.test.py
)
for authority_path in "${authority_paths[@]}"; do
  printf 'SCHEMA = "chio.security-check-authority.v%s"\n' '2' > "${fixture}/${authority_path}"
  bash "${fixture}/scripts/check-chio-owned-v1-only.sh" >/dev/null
  rm "${fixture}/${authority_path}"
done

require_authority_refusal() {
  local checker_status=0
  local checker_output
  checker_output="$(bash "${fixture}/scripts/check-chio-owned-v1-only.sh" 2>&1)" || checker_status=$?
  if ((checker_status != 1)) || [[ "$checker_output" != *"Core capability or receipt v1 contract remnants found:"* ]]; then
    echo "authority namespace refusal returned an unexpected result" >&2
    exit 1
  fi
}
printf 'SCHEMA = "chio.security-check-authority.v%s"\n' '2' > "${fixture}/scripts/unreviewed.py"
require_authority_refusal
rm "${fixture}/scripts/unreviewed.py"
for authority_version in 3 9 10 11 20 90; do
  printf 'SCHEMA = "chio.security-check-authority.v%s"\n' "$authority_version" \
    > "${fixture}/scripts/audit-security-merge-qualification.py"
  require_authority_refusal
done
printf 'SCHEMA = "chio.security-check-authority.v%s"; struct Receipt%s;\n' '2' 'V2' \
  > "${fixture}/scripts/audit-security-merge-qualification.py"
require_authority_refusal
printf 'SCHEMA = "chio.security-check-authority.v%s"\n' '2' \
  > "${fixture}/scripts/audit-security-merge-qualification.py"

# Existing explicitly declared negative corpora retain their fixture policy.
mkdir -p "${fixture}/scripts/negative-fixture-corpus"
printf 'SCHEMA = "chio.security-check-authority.v%s"\n' '90' \
  > "${fixture}/scripts/negative-fixture-corpus/future.py"
bash "${fixture}/scripts/check-chio-owned-v1-only.sh" >/dev/null
rm "${fixture}/scripts/negative-fixture-corpus/future.py"

# A scanner I/O error must fail the gate instead of authorizing the exemption.
real_rg="$(command -v rg)"
mkdir "${fixture}/tools"
cat > "${fixture}/tools/rg" <<'MOCK_RG'
#!/usr/bin/env bash
if [[ "${1:-}" == "-q" ]]; then
  exit 2
fi
exec "$CHIO_V1_TEST_REAL_RG" "$@"
MOCK_RG
chmod +x "${fixture}/tools/rg"
scanner_status=0
CHIO_V1_TEST_REAL_RG="$real_rg" PATH="${fixture}/tools:$PATH" \
  bash "${fixture}/scripts/check-chio-owned-v1-only.sh" >/dev/null 2>&1 || scanner_status=$?
if ((scanner_status != 2)); then
  echo "scanner failure did not preserve its operational exit" >&2
  exit 1
fi

echo "Core v1 version gate contract passed"
