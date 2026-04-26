#!/usr/bin/env bash
# mutants-gate.sh - Decide advisory or blocking posture for cargo-mutants.
#
# Source-doc anchor:
#   .planning/trajectory/02-fuzzing-post-pr13.md
#   "Mutation-testing CI shape (Phase 3)" -> advisory/blocking flip via
#   releases.toml. Decision lock: id=mutation-testing-gate-posture
#   (advisory for one release cycle after M02 P3 merges, blocking
#   thereafter; flip event is the next release tag).
#
# Reads releases.toml at the repository root:
#
#   [mutants]
#   phase3_merge_tag = "vX.Y.Z"   # tag of the M02 P3 merge release
#   cycle_end_tag    = ""          # filled in by the next release after P3
#
# Posture rule:
#   - cycle_end_tag empty (default today)  -> advisory; exit 0 unconditionally.
#   - cycle_end_tag non-empty               -> blocking; exit 1 when the
#                                              upstream cargo-mutants step
#                                              reported a non-zero exit
#                                              (surviving mutants beyond
#                                              the per-crate budget).
#
# Environment:
#   MUTANTS_PACKAGE     : crate name being scored (informational).
#   MUTANTS_OUTPUT_DIR  : directory holding cargo-mutants outcomes.json
#                         (informational; reserved for the M02 P3 catch-
#                         ratio threshold check).
#   MUTANTS_EXIT        : exit code from the cargo-mutants step
#                         (0 = clean, non-zero = survivors).
#
# Exit codes:
#   0 advisory pass (or blocking pass when survivors == 0)
#   1 blocking fail (cycle_end_tag non-empty AND survivors detected)
#
# This script is invoked by .github/workflows/mutants.yml's mutants-pr
# and mutants-nightly jobs. It is also safe to run locally:
#
#   MUTANTS_EXIT=0 bash scripts/mutants-gate.sh
#
# Today releases.toml ships with cycle_end_tag empty so this script
# always exits 0; the M02 P3 release-binaries auto-flip will populate
# cycle_end_tag and start enforcing without a workflow edit.

set -euo pipefail

PACKAGE="${MUTANTS_PACKAGE:-unknown}"
OUTPUT_DIR="${MUTANTS_OUTPUT_DIR:-}"
EXIT_CODE="${MUTANTS_EXIT:-0}"

# Locate releases.toml relative to the script. The script lives in
# scripts/ at the repo root, so releases.toml sits one directory up.
script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
releases_toml="${repo_root}/releases.toml"

if [[ ! -f "${releases_toml}" ]]; then
    printf 'mutants-gate: releases.toml missing at %s; defaulting to advisory\n' \
        "${releases_toml}" >&2
    printf 'mutants-gate: package=%s exit=%s posture=advisory verdict=pass\n' \
        "${PACKAGE}" "${EXIT_CODE}"
    exit 0
fi

# Extract cycle_end_tag value. Tolerate whitespace and quoting variants:
#   cycle_end_tag = ""
#   cycle_end_tag="vX.Y.Z"
# Stripped to the unquoted string. A pure-bash extractor avoids a TOML
# parser dependency on the runner.
cycle_end_tag=""
while IFS= read -r line; do
    # Strip leading and trailing whitespace.
    trimmed="${line#"${line%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    case "${trimmed}" in
        cycle_end_tag*=*)
            value="${trimmed#*=}"
            # Strip leading whitespace and surrounding double-quotes.
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value#\"}"
            value="${value%\"}"
            cycle_end_tag="${value}"
            break
            ;;
    esac
done < "${releases_toml}"

if [[ -z "${cycle_end_tag}" ]]; then
    printf 'mutants-gate: package=%s exit=%s posture=advisory verdict=pass (cycle_end_tag empty)\n' \
        "${PACKAGE}" "${EXIT_CODE}"
    exit 0
fi

# Blocking posture: cycle_end_tag is set. The cargo-mutants step exit
# code is the survivors signal; M02 P3's P3.T4 will replace this with a
# per-crate catch-ratio threshold check against outcomes.json under
# OUTPUT_DIR. Until then, any non-zero upstream exit fails the gate.
if [[ "${EXIT_CODE}" == "0" ]]; then
    printf 'mutants-gate: package=%s exit=0 posture=blocking verdict=pass (cycle_end_tag=%s)\n' \
        "${PACKAGE}" "${cycle_end_tag}"
    exit 0
fi

printf 'mutants-gate: package=%s exit=%s posture=blocking verdict=fail (cycle_end_tag=%s)\n' \
    "${PACKAGE}" "${EXIT_CODE}" "${cycle_end_tag}" >&2
if [[ -n "${OUTPUT_DIR}" && -d "${OUTPUT_DIR}" ]]; then
    printf 'mutants-gate: see %s for outcomes.json detail\n' "${OUTPUT_DIR}" >&2
fi
exit 1
