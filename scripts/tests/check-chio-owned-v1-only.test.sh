#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate_source="${root}/scripts/check-chio-owned-v1-only.sh"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# Version digits are spliced in at runtime so this file never matches the gate.
authority() { printf '"chio.security-check-authority.v%s"' "$1"; }
publication() { printf '"chio.security-check-publication.v%s"' "$1"; }

auditor=scripts/audit-security-merge-qualification.py
definitions=scripts/tests/check-security-definitions.test.py
auditor_v2_line="            and value.get(\"schema\") == $(authority 2)"
auditor_v3_line="            and value.get(\"schema\") == $(authority 3), \"invalid v3 authority metadata\")"
definitions_publication_line="                \"schema\": $(publication 2),"
definitions_authority_line="                    \"schema\": $(authority 3), \"identity\": IDENTITY,"

real_rg="$(command -v rg)"
mkdir "${work}/tools"
cat > "${work}/tools/rg" <<'MOCK_RG'
#!/usr/bin/env bash
# Fails only the scanner phase named by CHIO_V1_TEST_FAIL and records what that
# phase received, so each error case proves its target phase was reached.
phase=generic
for arg in "$@"; do
  if [[ "$arg" == '*.md' ]]; then
    phase=normative
  fi
done
if [[ "${1:-}" == -q ]]; then
  phase=recheck
fi
if [[ "$phase" == "${CHIO_V1_TEST_FAIL:-}" ]]; then
  if [[ "$phase" == recheck ]]; then
    cat >> "$CHIO_V1_TEST_REACHED"
  else
    printf '%s\n' "$phase" >> "$CHIO_V1_TEST_REACHED"
  fi
  exit 2
fi
exec "$CHIO_V1_TEST_REAL_RG" "$@"
MOCK_RG
chmod +x "${work}/tools/rg"

tree=""
new_tree() {
  tree="$(mktemp -d "${work}/tree.XXXXXX")"
  mkdir -p "${tree}"/{crates,spec,sdks,scripts,docs,formal,xtask}
  cp "$gate_source" "${tree}/scripts/check-chio-owned-v1-only.sh"
}

put() {
  mkdir -p "${tree}/$(dirname "$1")"
  printf '%s\n' "$2" >> "${tree}/$1"
}

failures=0
pass() { printf 'ok - %s\n' "$1"; }
fail() {
  printf 'FAILED - %s: %s\n' "$1" "$2" >&2
  failures=$((failures + 1))
}

gate_status=0
gate_output=""
run_gate() {
  gate_status=0
  gate_output="$(bash "${tree}/scripts/check-chio-owned-v1-only.sh" 2>&1)" || gate_status=$?
}

expect_admitted() {
  run_gate
  if ((gate_status == 0)) && [[ "$gate_output" == "No Chio-owned pre-release version remnants found." ]]; then
    pass "$1"
  else
    fail "$1" "expected admission, got status ${gate_status}: ${gate_output}"
  fi
}

# The refused tree holds exactly one hit, at line 1 of the named path.
expect_refused() {
  local expected
  expected="Chio-owned pre-release version remnants found:"$'\n'"  $2:1:$3"
  run_gate
  if ((gate_status == 1)) && [[ "$gate_output" == "$expected" ]]; then
    pass "$1"
  else
    fail "$1" "expected refusal of $2:1, got status ${gate_status}: ${gate_output}"
  fi
}

refuse_single() {
  new_tree
  put "$2" "$3"
  expect_refused "$1" "$2" "$3"
}

expect_scanner_error() {
  local name="$1" phase="$2" message="$3" reached_input="$4"
  local reached="${tree}.reached" observed=""
  gate_status=0
  gate_output="$(CHIO_V1_TEST_FAIL="$phase" CHIO_V1_TEST_REACHED="$reached" CHIO_V1_TEST_REAL_RG="$real_rg" \
    PATH="${work}/tools:${PATH}" bash "${tree}/scripts/check-chio-owned-v1-only.sh" 2>&1)" || gate_status=$?
  if [[ -f "$reached" ]]; then
    observed="$(cat "$reached")"
  fi
  if ((gate_status == 2)) && [[ "$gate_output" == "$message"* ]] && [[ "$observed" == "$reached_input" ]]; then
    pass "$name"
  else
    fail "$name" "expected ${phase} scanner failure, got status ${gate_status}, reached [${observed}]: ${gate_output}"
  fi
}

new_tree
expect_admitted baseline_empty_tree_passes

# Reviewed internal App check metadata literals, each in its exact reviewed path.
new_tree
put "$auditor" "$auditor_v3_line"
expect_admitted auditor_v3_authority_admitted
new_tree
put "$definitions" "$definitions_authority_line"
expect_admitted definitions_v3_authority_admitted
new_tree
put "$definitions" "$definitions_publication_line"
expect_admitted definitions_v2_publication_admitted
new_tree
put "$auditor" "$auditor_v3_line"
put "$definitions" "$definitions_publication_line"
put "$definitions" "$definitions_authority_line"
expect_admitted trusted_definition_shape_admitted

# The auditor reads only the v3 authority; its superseded v2 literal is refused.
refuse_single auditor_v2_authority_refused "$auditor" "$auditor_v2_line"

# The same literals are refused in every path that was not reviewed for them.
reviewed_lines=("$auditor_v3_line" "$definitions_authority_line" "$definitions_publication_line")
unreviewed_paths=(
  scripts/unreviewed.py
  scripts/tests/unreviewed.test.py
  crates/vendor/scripts/audit-security-merge-qualification.py
  crates/vendor/scripts/tests/check-security-definitions.test.py
  "${auditor}.orig"
  "${definitions}.orig"
)
for index in "${!reviewed_lines[@]}"; do
  for path in "${unreviewed_paths[@]}"; do
    refuse_single "unreviewed_path_refused[${index}:${path}]" "$path" "${reviewed_lines[$index]}"
  done
done
refuse_single auditor_refuses_definitions_publication "$auditor" "$definitions_publication_line"
refuse_single definitions_refuse_auditor_v2_authority "$definitions" "$auditor_v2_line"

# Unreviewed versions stay refused in the reviewed paths.
for version in 4 8 30; do
  refuse_single "auditor_authority_v${version}_refused" "$auditor" \
    "            and value.get(\"schema\") == $(authority "$version")"
  refuse_single "definitions_authority_v${version}_refused" "$definitions" \
    "                    \"schema\": $(authority "$version"), \"identity\": IDENTITY,"
done
for version in 3 4 30; do
  refuse_single "definitions_publication_v${version}_refused" "$definitions" \
    "                \"schema\": $(publication "$version"),"
done

# A reviewed literal never hides an adjacent core-wire or normative claim.
reviewed_paths=("$auditor" "$definitions" "$definitions")
adjacent_claims=(
  "$(printf '  # Receipt%s' V2)"
  "$(printf '  # CapabilityToken%s' V2)"
  "$(printf '  # current protocol is v%s' 2)"
)
for index in "${!reviewed_lines[@]}"; do
  for claim_index in "${!adjacent_claims[@]}"; do
    refuse_single "adjacent_claim_refused[${index}:${claim_index}]" "${reviewed_paths[$index]}" \
      "${reviewed_lines[$index]}${adjacent_claims[$claim_index]}"
  done
done
refuse_single auditor_adjacent_publication_refused "$auditor" "${auditor_v3_line}, $(publication 2)"
refuse_single definitions_adjacent_auditor_v2_refused "$definitions" "${definitions_authority_line} $(authority 2)"

# Other generic hits in the reviewed paths, including inexact spellings of the
# reviewed literals, remain refused.
refuse_single auditor_receipt_refused "$auditor" "$(printf 'struct Receipt%s:' V2)"
refuse_single auditor_unquoted_authority_refused "$auditor" "$(printf '# requires chio.security-check-authority.v%s' 3)"
refuse_single auditor_single_quoted_authority_refused "$auditor" "$(printf "SCHEMA = 'chio.security-check-authority.v%s'" 3)"
refuse_single definitions_receipt_schema_refused "$definitions" "$(printf 'SCHEMA = "chio.receipt.v%s"' 2)"
refuse_single definitions_unquoted_publication_refused "$definitions" "$(printf '# emits chio.security-check-publication.v%s' 2)"
refuse_single definitions_single_quoted_authority_refused "$definitions" "$(printf "SCHEMA = 'chio.security-check-authority.v%s'" 3)"
refuse_single core_capability_token_refused crates/core.rs "$(printf 'struct CapabilityToken%s;' V2)"
refuse_single normative_claim_refused docs/reference/version.md "$(printf 'The current protocol is v%s.' 2)"

# Scanner failures exit with the scanner status instead of admitting a line.
new_tree
put "$auditor" "$auditor_v3_line"
expect_scanner_error generic_scan_error_fails_closed generic \
  "ripgrep failed while scanning Chio-owned version remnants" generic
new_tree
put docs/reference/version.md "Chio protocol reference."
expect_scanner_error normative_scan_error_fails_closed normative \
  "ripgrep failed while scanning normative version claims" normative
new_tree
put "$auditor" "$auditor_v3_line"
expect_scanner_error auditor_v3_recheck_error_fails_closed recheck \
  "ripgrep failed while rechecking" '            and value.get("schema") == , "invalid v3 authority metadata")'
new_tree
put "$definitions" "$definitions_authority_line"
expect_scanner_error definitions_authority_recheck_error_fails_closed recheck \
  "ripgrep failed while rechecking" '                    "schema": , "identity": IDENTITY,'
new_tree
put "$definitions" "$definitions_publication_line"
expect_scanner_error definitions_publication_recheck_error_fails_closed recheck \
  "ripgrep failed while rechecking" '                "schema": ,'

if ((failures)); then
  printf 'check-chio-owned-v1-only.test.sh: %d case(s) failed\n' "$failures" >&2
  exit 1
fi
echo "check-chio-owned-v1-only.test.sh: version gate contract passed"
