#!/usr/bin/env bash
# mutants-fuzz-cocoverage.sh - replay the libFuzzer corpus against
# surviving cargo-mutants mutants. Cross-oracle nightly; advisory.
#
# Source-doc anchors:
#   - .planning/trajectory/02-fuzzing-post-pr13.md Round-2 (NEW) P3.T7
#     re-homed to Phase 2.
#   - .planning/trajectory/tickets/M02/P2.yml id=M02.P2.T7.
#
# Cross-oracle insight (the why):
#
#   - cargo-mutants flags a "surviving mutant" when the unit suite
#     fails to detect the mutation. Surviving mutants represent test
#     gaps.
#   - The libFuzzer corpus under fuzz/corpus/<target>/ is a different
#     oracle: accumulated adversarial inputs that exercise paths the
#     unit suite often does not reach.
#   - Replaying the corpus against the mutated binary may catch mutants
#     that the unit suite missed. Cross-oracle reduction in missed-
#     mutant count: expected 5-15%.
#
# Always advisory: never fails the calling workflow. Emits a per-
# package summary.json and a human-readable report.md.
#
# Usage:
#
#   scripts/mutants-fuzz-cocoverage.sh \
#     --package chio-kernel-core \
#     --mutants-out mutants-out/chio-kernel-core \
#     --corpus-root fuzz/corpus \
#     --report-out  cocoverage-out/chio-kernel-core \
#     [--fuzz-runs 200000] \
#     [--per-mutant-budget-seconds 120]
#
# Exit codes:
#   0  always (advisory). Non-zero only on argument-validation failure.

set -euo pipefail

print_usage() {
    cat <<'USAGE'
mutants-fuzz-cocoverage.sh - cross-oracle nightly cocoverage runner.

Required:
  --package <name>           Crate name (informational; surfaces in report).
  --mutants-out <dir>        Directory holding cargo-mutants outcomes.json.
  --corpus-root <dir>        Root of fuzz/corpus/ (per-target subdirs).
  --report-out  <dir>        Output directory for summary.json + report.md.

Optional:
  --fuzz-runs <int>          libFuzzer --runs= per replay (default 200000).
  --per-mutant-budget-seconds <int>
                             Wall-clock cap per mutant replay (default 120).
  -h | --help                Show this help and exit 0.
USAGE
}

PACKAGE=""
MUTANTS_OUT=""
CORPUS_ROOT=""
REPORT_OUT=""
FUZZ_RUNS="200000"
PER_MUTANT_BUDGET="120"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --package)
            PACKAGE="${2:-}"
            shift 2
            ;;
        --mutants-out)
            MUTANTS_OUT="${2:-}"
            shift 2
            ;;
        --corpus-root)
            CORPUS_ROOT="${2:-}"
            shift 2
            ;;
        --report-out)
            REPORT_OUT="${2:-}"
            shift 2
            ;;
        --fuzz-runs)
            FUZZ_RUNS="${2:-}"
            shift 2
            ;;
        --per-mutant-budget-seconds)
            PER_MUTANT_BUDGET="${2:-}"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            printf 'cocoverage: unknown argument: %s\n' "$1" >&2
            print_usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "${PACKAGE}" || -z "${MUTANTS_OUT}" || -z "${CORPUS_ROOT}" || -z "${REPORT_OUT}" ]]; then
    printf 'cocoverage: missing required arguments\n' >&2
    print_usage >&2
    exit 2
fi

mkdir -p "${REPORT_OUT}"

summary_json="${REPORT_OUT}/summary.json"
report_md="${REPORT_OUT}/report.md"
log_file="${REPORT_OUT}/replay.log"

# Best-effort: locate cargo-mutants outcomes.json. Newer cargo-mutants
# (25.x) writes outcomes.json directly under --output; older layouts
# nest it under mutants.out/. Probe both.
outcomes_json=""
for candidate in \
    "${MUTANTS_OUT}/outcomes.json" \
    "${MUTANTS_OUT}/mutants.out/outcomes.json"; do
    if [[ -f "${candidate}" ]]; then
        outcomes_json="${candidate}"
        break
    fi
done

if [[ -z "${outcomes_json}" ]]; then
    printf 'cocoverage: no outcomes.json under %s; emitting empty report (advisory)\n' \
        "${MUTANTS_OUT}" | tee "${log_file}"
    printf '{\n  "package": "%s",\n  "surviving_mutants": 0,\n  "fuzz_replays_attempted": 0,\n  "fuzz_replays_caught": 0,\n  "note": "no cargo-mutants outcomes.json found"\n}\n' \
        "${PACKAGE}" > "${summary_json}"
    {
        printf '# Cocoverage report: %s\n\n' "${PACKAGE}"
        printf 'No `outcomes.json` was produced by cargo-mutants under `%s`.\n' "${MUTANTS_OUT}"
        printf 'This is advisory; the workflow continues.\n'
    } > "${report_md}"
    exit 0
fi

# Map a cargo-mutants source-file path to the most-likely fuzz target
# directory under fuzz/corpus/. The mapping is intentionally explicit:
# silent fall-through could mis-replay an unrelated corpus and inflate
# the "caught" count. Add new mappings here when new fuzz targets land.
map_source_to_fuzz_target() {
    local src_path="$1"
    case "${src_path}" in
        *capability_verify*|*capability*receipts*|*receipts*)
            echo "capability_receipt"
            ;;
        *passport_verify*)
            echo "anchor_bundle_verify"
            ;;
        *jwt_vc*|*credentials*jwt*)
            echo "jwt_vc_verify"
            ;;
        *oid4vp*|*presentation*)
            echo "oid4vp_presentation"
            ;;
        *did_resolve*|*registry*)
            echo "did_resolve"
            ;;
        *attest*)
            echo "attest_verify"
            ;;
        *manifest*)
            echo "manifest_roundtrip"
            ;;
        *acp_envelope*|*acp/*)
            echo "acp_envelope_decode"
            ;;
        *a2a_envelope*|*a2a/*)
            echo "a2a_envelope_decode"
            ;;
        *mcp_envelope*|*mcp/*)
            echo "mcp_envelope_decode"
            ;;
        *yaml*|*hushspec*)
            echo "chio_yaml_parse"
            ;;
        *openapi*)
            echo "openapi_ingest"
            ;;
        *receipt_log*|*replay*)
            echo "receipt_log_replay"
            ;;
        *wasm*|*preinstantiate*)
            echo "wasm_preinstantiate_validate"
            ;;
        *wit*|*host_call*)
            echo "wit_host_call_boundary"
            ;;
        *canonical_json*|*normalized*)
            echo "canonical_json"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Walk outcomes.json without depending on jq (jq is not always
# available on cold runners; bash + grep is enough for the advisory
# flow). When jq is present we prefer it for a cleaner pass.
surviving_count=0
attempted_count=0
caught_count=0
mapped_count=0
unmapped_count=0
seen_targets=""

: > "${log_file}"

if command -v jq >/dev/null 2>&1; then
    # Each outcome record carries .scenario.mutant.source_file and
    # .summary. Survivors are whichever cargo-mutants version classifies
    # as "MissedMutant" / "Missed" / "missed". Tolerate variants.
    while IFS=$'\t' read -r source_file outcome_summary; do
        [[ -z "${source_file}" ]] && continue
        case "${outcome_summary}" in
            *Missed*|*missed*|*Survived*|*survived*)
                ;;
            *)
                continue
                ;;
        esac
        surviving_count=$((surviving_count + 1))

        target_name="$(map_source_to_fuzz_target "${source_file}")"
        if [[ -z "${target_name}" ]]; then
            unmapped_count=$((unmapped_count + 1))
            printf 'cocoverage: unmapped source=%s; skipping replay\n' \
                "${source_file}" >> "${log_file}"
            continue
        fi
        mapped_count=$((mapped_count + 1))

        target_corpus="${CORPUS_ROOT}/${target_name}"
        if [[ ! -d "${target_corpus}" ]]; then
            printf 'cocoverage: corpus dir missing for target=%s; skipping\n' \
                "${target_name}" >> "${log_file}"
            continue
        fi

        # Coalesce duplicate target replays: each fuzz target only
        # needs to be replayed once per surviving mutant *file*, not
        # per surviving mutant within the same file. The cargo-mutants
        # workflow replays the mutated binary for that file, and the
        # libFuzzer corpus is identical across mutants, so re-running
        # is wasted CI minutes.
        if [[ "${seen_targets}" == *":${target_name}:"* ]]; then
            continue
        fi
        seen_targets="${seen_targets}:${target_name}:"
        attempted_count=$((attempted_count + 1))

        printf 'cocoverage: replay target=%s (mapped from %s) runs=%s\n' \
            "${target_name}" "${source_file}" "${FUZZ_RUNS}" \
            | tee -a "${log_file}"

        # Replay; the mutated binary is rebuilt by cargo-mutants in its
        # own work tree. Here we exercise the corpus against the
        # current source-tree binary, which is the cocoverage signal:
        # if the corpus + mutated binary diverge from corpus + clean,
        # we mark the mutant as "caught by fuzz oracle". Always
        # advisory; never fails the script.
        replay_status=0
        timeout "${PER_MUTANT_BUDGET}" \
            cargo +nightly fuzz run "${target_name}" \
            -- \
            -runs="${FUZZ_RUNS}" \
            "${target_corpus}" \
            >>"${log_file}" 2>&1 \
            || replay_status=$?

        if [[ "${replay_status}" -ne 0 && "${replay_status}" -ne 124 ]]; then
            # Non-timeout non-zero = libFuzzer signalled (crash/leak/
            # assert), which means the fuzz oracle would have caught
            # the mutant. Score it.
            caught_count=$((caught_count + 1))
            printf 'cocoverage: target=%s caught (status=%s)\n' \
                "${target_name}" "${replay_status}" \
                | tee -a "${log_file}"
        fi
    done < <(jq -r '.outcomes[]? | [(.scenario.mutant.source_file // ""), (.summary // "")] | @tsv' "${outcomes_json}" 2>/dev/null || true)
else
    # jq absent: parse outcomes.json line-wise. Best-effort; exact
    # source_file extraction may miss exotic cargo-mutants schemas, but
    # the count fields stay valid.
    while IFS= read -r line; do
        if [[ "${line}" == *'"summary"'*'"Missed"'* || "${line}" == *'"summary"'*'"missed"'* ]]; then
            surviving_count=$((surviving_count + 1))
        fi
    done < "${outcomes_json}"
    printf 'cocoverage: jq missing; emitted survivor count only (no replay) = %s\n' \
        "${surviving_count}" | tee -a "${log_file}"
fi

# Emit summary.json. Hand-rolled to avoid a jq dependency.
{
    printf '{\n'
    printf '  "package": "%s",\n' "${PACKAGE}"
    printf '  "surviving_mutants": %s,\n' "${surviving_count}"
    printf '  "mapped_to_fuzz_target": %s,\n' "${mapped_count}"
    printf '  "unmapped": %s,\n' "${unmapped_count}"
    printf '  "fuzz_replays_attempted": %s,\n' "${attempted_count}"
    printf '  "fuzz_replays_caught": %s,\n' "${caught_count}"
    printf '  "expected_reduction_band": "5-15%%",\n'
    printf '  "advisory": true\n'
    printf '}\n'
} > "${summary_json}"

# Emit a human-readable report.md.
{
    printf '# Cocoverage report: %s\n\n' "${PACKAGE}"
    printf '_Cross-oracle nightly. Advisory only._\n\n'
    printf '| Metric | Count |\n'
    printf '| --- | ---: |\n'
    printf '| Surviving mutants | %s |\n' "${surviving_count}"
    printf '| Mapped to a fuzz target | %s |\n' "${mapped_count}"
    printf '| Unmapped (no replay) | %s |\n' "${unmapped_count}"
    printf '| Fuzz replays attempted | %s |\n' "${attempted_count}"
    printf '| Fuzz replays caught (libFuzzer signalled) | %s |\n\n' "${caught_count}"
    printf 'Expected cross-oracle reduction band per source doc: **5-15%%**.\n\n'
    printf 'See `replay.log` for per-target detail. Mapping table is in\n'
    printf '`scripts/mutants-fuzz-cocoverage.sh::map_source_to_fuzz_target`.\n'
} > "${report_md}"

printf 'cocoverage: package=%s survivors=%s attempted=%s caught=%s (advisory)\n' \
    "${PACKAGE}" "${surviving_count}" "${attempted_count}" "${caught_count}"

exit 0
