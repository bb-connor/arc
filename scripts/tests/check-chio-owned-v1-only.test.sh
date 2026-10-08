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


# Internal App authority metadata is confined to exact reviewed paths and
# literals: quoted v3 in the reviewed producers, validators and regression
# suites, backtick-quoted v3 in the reviewed evidence narrative, and quoted v2
# only as the legacy record that the contract checker and identity regressions
# must refuse.
rm "${fixture}/crates/core-receipt.rs"
gate="${fixture}/scripts/check-chio-owned-v1-only.sh"
auditor=scripts/audit-security-merge-qualification.py
contract_checker=scripts/check-security-ci-contract.py
definitions_suite=scripts/tests/check-security-definitions.test.py
identity_suite=scripts/tests/trusted-ci-identity-regressions.test.py
landing_suite=scripts/tests/trusted-ci-landing-regressions.test.py
revocation_suite=scripts/tests/trusted-ci-revocation-regressions.test.py
main_codegen_suite=scripts/tests/trusted-main-codegen-regressions.test.py
evidence_doc=docs/security/committed-linux-evidence.md
authority_paths=(
  "$auditor"
  "$contract_checker"
  "$definitions_suite"
  "$identity_suite"
  "$landing_suite"
  "$revocation_suite"
  "$main_codegen_suite"
)
legacy_marker_paths=("$contract_checker" "$identity_suite")
legacy_refusing_paths=("$auditor" "$definitions_suite" "$landing_suite" "$revocation_suite" "$main_codegen_suite")
unreviewed_paths=(
  scripts/unreviewed.py
  "scripts/tests/nested/${identity_suite##*/}"
  "crates/${contract_checker}"
  "${identity_suite}.orig"
)

# Fixture text is assembled from parts so this suite is not itself a gate site.
authority() { printf 'chio.security-check-authority.v%s' "$1"; }
core_receipt="struct Receipt""V2;"
core_token="CapabilityToken""V2"
normative_claim="Current protocol is v""2"

contract_failures=()
expect_gate() {
  local expectation="$1" label="$2" path="$3" text="$4"
  local status=0 output
  mkdir -p "$(dirname "${fixture}/${path}")"
  printf '%s\n' "$text" > "${fixture}/${path}"
  output="$(bash "$gate" 2>&1)" || status=$?
  rm "${fixture}/${path}"
  if [[ "$expectation" == allow ]]; then
    if ((status == 0)); then
      printf 'ok %s\n' "$label"
      return
    fi
  elif ((status == 1)) &&
       [[ "$output" == *"Core capability or receipt v1 contract remnants found:"* ]] &&
       [[ "$output" == *"  ${path}:1:${text}"* ]]; then
    printf 'ok %s\n' "$label"
    return
  fi
  printf 'FAILED %s (status %s)\n' "$label" "$status"
  contract_failures+=("${label}: status ${status}: ${output}")
}

for path in "${authority_paths[@]}"; do
  expect_gate allow "reviewed quoted v3 in ${path}" "$path" "SCHEMA = \"$(authority 3)\""
done
for path in "${legacy_marker_paths[@]}"; do
  expect_gate allow "legacy quoted v2 refusal record in ${path}" "$path" "SCHEMA = \"$(authority 2)\""
done
expect_gate allow "reviewed backtick v3 in ${evidence_doc}" "$evidence_doc" \
  "Its strict \`$(authority 3)\` text carries \`I\` and \`K\`."

# Every other authority version stays refused, in reviewed paths too.
for path in "${authority_paths[@]}"; do
  expect_gate refuse "quoted v4 in ${path}" "$path" "SCHEMA = \"$(authority 4)\""
done
for version in 9 10 11 20 30 33 90; do
  expect_gate refuse "quoted v${version} in ${auditor}" "$auditor" "SCHEMA = \"$(authority "$version")\""
done
for path in "${legacy_marker_paths[@]}"; do
  for version in 20 22; do
    expect_gate refuse "quoted v${version} in ${path}" "$path" "SCHEMA = \"$(authority "$version")\""
  done
done
for version in 2 4 30; do
  expect_gate refuse "backtick v${version} in ${evidence_doc}" "$evidence_doc" "Its strict \`$(authority "$version")\` text"
done

# The legacy v2 record is not producer-wide.
for path in "${legacy_refusing_paths[@]}"; do
  expect_gate refuse "quoted v2 in ${path}" "$path" "SCHEMA = \"$(authority 2)\""
done

# Unreviewed and near-miss paths get no exemption.
for path in "${unreviewed_paths[@]}"; do
  for version in 2 3; do
    expect_gate refuse "quoted v${version} in unreviewed ${path}" "$path" "SCHEMA = \"$(authority "$version")\""
  done
done
expect_gate refuse "backtick v3 in unreviewed docs/security/other-evidence.md" \
  docs/security/other-evidence.md "Its strict \`$(authority 3)\` text"

# Each exemption covers only its exact reviewed quoting.
for path in "$auditor" "$contract_checker" "$identity_suite"; do
  expect_gate refuse "backtick v3 in ${path}" "$path" "SCHEMA = \`$(authority 3)\`"
  expect_gate refuse "single-quoted v3 in ${path}" "$path" "SCHEMA = '$(authority 3)'"
  expect_gate refuse "bare v3 in ${path}" "$path" "SCHEMA = $(authority 3)"
done
for path in "${legacy_marker_paths[@]}"; do
  expect_gate refuse "backtick v2 in ${path}" "$path" "SCHEMA = \`$(authority 2)\`"
  expect_gate refuse "single-quoted v2 in ${path}" "$path" "SCHEMA = '$(authority 2)'"
done
expect_gate refuse "quoted v3 in ${evidence_doc}" "$evidence_doc" "SCHEMA = \"$(authority 3)\""
expect_gate refuse "single-quoted v3 in ${evidence_doc}" "$evidence_doc" "SCHEMA = '$(authority 3)'"
expect_gate refuse "bare v3 in ${evidence_doc}" "$evidence_doc" "Its strict $(authority 3) text"

# An exempt identifier cannot hide an adjacent core-wire, normative or
# authority claim on the same line.
for adjacent in "$core_receipt" "$core_token" "$normative_claim" "\"$(authority 4)\""; do
  for path in "${authority_paths[@]}"; do
    expect_gate refuse "quoted v3 beside ${adjacent} in ${path}" "$path" "SCHEMA = \"$(authority 3)\"; ${adjacent}"
  done
  for path in "${legacy_marker_paths[@]}"; do
    expect_gate refuse "quoted v2 beside ${adjacent} in ${path}" "$path" "SCHEMA = \"$(authority 2)\"; ${adjacent}"
  done
  expect_gate refuse "backtick v3 beside ${adjacent} in ${evidence_doc}" "$evidence_doc" \
    "Its strict \`$(authority 3)\` text; ${adjacent}"
done
for path in "${legacy_refusing_paths[@]}"; do
  expect_gate refuse "quoted v3 beside quoted v2 in ${path}" "$path" \
    "SCHEMA = \"$(authority 3)\"; LEGACY = \"$(authority 2)\""
done
expect_gate refuse "backtick v3 beside quoted v2 in ${evidence_doc}" "$evidence_doc" \
  "Its strict \`$(authority 3)\` text; \"$(authority 2)\""

# Existing explicitly declared negative corpora retain their fixture policy.
expect_gate allow "declared negative corpus keeps its fixture policy" \
  scripts/negative-fixture-corpus/future.py "SCHEMA = \"$(authority 90)\""

# A scanner I/O error must fail the gate instead of authorizing the exemption.
real_rg="$(command -v rg)"
mkdir "${fixture}/tools"
cat > "${fixture}/tools/rg" <<'MOCK_RG'
#!/usr/bin/env bash
# Only the broad post-strip recheck of an exempt line gets an I/O error.
# The later authority-namespace query must use the real scanner result.
if [[ "${1:-}" == "-q" && "${2:-}" == *'ReceiptV[2-9]'* ]]; then
  scanner_input="$(cat)"
  if [[ "$scanner_input" == 'SCHEMA = ' ]]; then
    printf '%s\n' 'authority-post-strip-recheck' >> "$CHIO_V1_TEST_TARGET_REACHED"
    exit 2
  fi
  printf '%s\n' "$scanner_input" | "$CHIO_V1_TEST_REAL_RG" "$@"
  exit "$?"
fi
exec "$CHIO_V1_TEST_REAL_RG" "$@"
MOCK_RG
chmod +x "${fixture}/tools/rg"
scanner_target_reached="${fixture}/scanner-target-reached"
expect_scanner_failure() {
  local label="$1" path="$2" text="$3"
  local status=0
  rm -f "$scanner_target_reached"
  printf '%s\n' "$text" > "${fixture}/${path}"
  CHIO_V1_TEST_REAL_RG="$real_rg" CHIO_V1_TEST_TARGET_REACHED="$scanner_target_reached" PATH="${fixture}/tools:$PATH" \
    bash "$gate" >/dev/null 2>&1 || status=$?
  rm "${fixture}/${path}"
  if [[ -f "$scanner_target_reached" ]] &&
     [[ "$(cat "$scanner_target_reached")" == 'authority-post-strip-recheck' ]] &&
     ((status == 2)); then
    printf 'ok %s\n' "$label"
    return
  fi
  printf 'FAILED %s (status %s)\n' "$label" "$status"
  contract_failures+=("${label}: status ${status}: post-strip recheck fault not reached exactly once with its operational exit")
}
expect_scanner_failure "scanner error on the quoted v3 recheck in ${auditor}" \
  "$auditor" "SCHEMA = \"$(authority 3)\""
expect_scanner_failure "scanner error on the quoted v2 recheck in ${contract_checker}" \
  "$contract_checker" "SCHEMA = \"$(authority 2)\""
expect_scanner_failure "scanner error on the quoted v2 recheck in ${identity_suite}" \
  "$identity_suite" "SCHEMA = \"$(authority 2)\""
expect_scanner_failure "scanner error on the backtick v3 recheck in ${evidence_doc}" \
  "$evidence_doc" "SCHEMA = \`$(authority 3)\`"

if ((${#contract_failures[@]})); then
  printf '%s\n' "Authority namespace contract failures:" >&2
  printf '  %s\n' "${contract_failures[@]}" >&2
  exit 1
fi

echo "Core v1 version gate contract passed"
