#!/usr/bin/env bash
# scripts/check-mapping.sh
#
# Cross-reference gate for formal/MAPPING.md. Asserts that every named
# TLA+ safety/liveness invariant in formal/tla/RevocationPropagation.tla
# and every #[kani::proof] harness in
# crates/chio-kernel-core/src/kani_public_harnesses.rs has a
# corresponding row in formal/MAPPING.md. Exits non-zero with a
# human-readable diff if any property is unmapped.
#
# Owner: M03.P3.T5 (formal/MAPPING.md, scripts/check-mapping.sh).
# Source of truth: .planning/trajectory/03-capability-algebra-properties.md
# Phase 3 task 5.

set -euo pipefail

# --- Repo root ---------------------------------------------------------------
# Resolve to the repo root regardless of where the script is invoked from.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

mapping="formal/MAPPING.md"
tla="formal/tla/RevocationPropagation.tla"
kani="crates/chio-kernel-core/src/kani_public_harnesses.rs"

# --- Sanity: source files must exist ----------------------------------------
missing_inputs=0
for f in "${mapping}" "${tla}" "${kani}"; do
  if [[ ! -f "${f}" ]]; then
    echo "check-mapping: required input is missing: ${f}" >&2
    missing_inputs=1
  fi
done
if [[ "${missing_inputs}" -ne 0 ]]; then
  exit 1
fi

# --- TLA+ named invariants ---------------------------------------------------
# The named-invariants whitelist below is the canonical set of safety /
# liveness invariants for RevocationPropagation as documented in the phase
# doc and the M03.P3.T2 / T3 ticket specs. We require: any whitelisted name
# that is *defined* in the .tla file (top-level `<Name> ==`) must appear as
# a row in MAPPING.md. Whitelisted-but-undefined is fine; that is just
# "future work" (e.g. RevocationEventuallySeen lands at T3, not yet).
#
# Helper definitions like DomainsOK, States, Verdicts, ProcSet, CapSet,
# DEPTH_MAX, Init, Next, Spec, vars, Receipt, Message, Attenuate, Revoke,
# Propagate, Evaluate, and the aggregate SafetyInv are intentionally NOT
# enforced: they are not the named invariants the trajectory doc and the
# Apalache .cfg cite. The aggregate SafetyInv is the conjunction the .cfg
# checks; the leaf-named invariants below are the unit of cross-reference.
named_tla_invariants=(
  "NoAllowAfterRevoke"
  "MonotoneLog"
  "AttenuationPreserving"
  "RevocationEventuallySeen"
)

defined_tla_invariants=()
for name in "${named_tla_invariants[@]}"; do
  # Match a top-level definition `<name> ==` (allowing whitespace before ==).
  # Does NOT match references inside other definitions because the regex is
  # anchored at the start of the line.
  if grep -qE "^${name}[[:space:]]*==" "${tla}"; then
    defined_tla_invariants+=("${name}")
  fi
done

# --- Kani #[kani::proof] harnesses ------------------------------------------
# Extract the function name on the line immediately following each
# #[kani::proof] attribute. The harness body and helper functions are
# intentionally ignored.
#
# Portability: this script targets bash 3.2 (default macOS) and BSD awk.
# That rules out `mapfile` and the gawk-only 3-arg `match()`. We use a
# two-pass awk that captures the line after the attribute, then a sub()
# / gsub() to strip everything except the identifier.
kani_harness_list="$(
  awk '
    /^#\[kani::proof\]/ { want = 1; next }
    want {
      line = $0
      # Strip leading whitespace and the leading `fn ` keyword.
      sub(/^[[:space:]]+/, "", line)
      sub(/^fn[[:space:]]+/, "", line)
      # Strip everything from the first `(` onward.
      sub(/\(.*/, "", line)
      # Strip any residual whitespace.
      sub(/[[:space:]]+$/, "", line)
      if (line != "") {
        print line
      }
      want = 0
    }
  ' "${kani}" | LC_ALL=C sort
)"

kani_harnesses=()
if [[ -n "${kani_harness_list}" ]]; then
  while IFS= read -r line; do
    kani_harnesses+=("${line}")
  done <<< "${kani_harness_list}"
fi

# --- Mapping presence check --------------------------------------------------
# For each enforced name, require it to appear as `<name>` (backtick-wrapped)
# in formal/MAPPING.md. Backtick wrapping is the canonical form used in the
# table rows and is what authors should use when they add a new row.
unmapped_tla=()
for name in "${defined_tla_invariants[@]}"; do
  if ! grep -qF "\`${name}\`" "${mapping}"; then
    unmapped_tla+=("${name}")
  fi
done

unmapped_kani=()
for name in "${kani_harnesses[@]}"; do
  # Skip empty entries that can arise if the file has no harnesses.
  if [[ -z "${name}" ]]; then
    continue
  fi
  if ! grep -qF "\`${name}\`" "${mapping}"; then
    unmapped_kani+=("${name}")
  fi
done

# --- Reporting ---------------------------------------------------------------
echo "check-mapping: scanning ${mapping}"
echo "  TLA+ invariants enforced (${#defined_tla_invariants[@]} of ${#named_tla_invariants[@]} whitelisted defined in ${tla}):"
for name in "${defined_tla_invariants[@]}"; do
  echo "    - ${name}"
done
echo "  Kani harnesses enforced (${#kani_harnesses[@]} from ${kani}):"
for name in "${kani_harnesses[@]}"; do
  if [[ -n "${name}" ]]; then
    echo "    - ${name}"
  fi
done

failures=0

if [[ "${#unmapped_tla[@]}" -gt 0 ]]; then
  failures=$((failures + ${#unmapped_tla[@]}))
  echo ""
  echo "check-mapping: FAIL - ${#unmapped_tla[@]} TLA+ invariant(s) defined in ${tla} but not cited in ${mapping}:" >&2
  for name in "${unmapped_tla[@]}"; do
    echo "  - ${name}" >&2
  done
  echo "" >&2
  echo "  Add a row to the 'TLA+ named invariants' table in ${mapping}." >&2
  echo "  The literal token must appear as \`${unmapped_tla[0]}\` (backtick-wrapped)." >&2
fi

if [[ "${#unmapped_kani[@]}" -gt 0 ]]; then
  failures=$((failures + ${#unmapped_kani[@]}))
  echo ""
  echo "check-mapping: FAIL - ${#unmapped_kani[@]} Kani harness(es) defined in ${kani} but not cited in ${mapping}:" >&2
  for name in "${unmapped_kani[@]}"; do
    echo "  - ${name}" >&2
  done
  echo "" >&2
  echo "  Add a row to the 'Kani public harnesses' table in ${mapping}." >&2
  echo "  The literal token must appear as \`${unmapped_kani[0]}\` (backtick-wrapped)." >&2
fi

if [[ "${failures}" -ne 0 ]]; then
  echo "" >&2
  echo "check-mapping: ${failures} unmapped property(ies). Failing closed." >&2
  exit 1
fi

echo ""
echo "check-mapping: OK - every enforced property is mapped."
exit 0
