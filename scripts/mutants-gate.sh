#!/usr/bin/env bash
# mutants-gate.sh - Decide advisory or blocking posture for cargo-mutants.
#
# Reads releases.toml at the repository root:
#
#   [mutants]
#   target_catch_ratio_percent = 80
#   activation_threshold_percent_per_crate = 65 # optional D08 floor
#   required_consecutive_nightly_successes = 2
#   observed_consecutive_nightly_successes = 0
#   cycle_end_tag = ""             # filled in after evidence and release
#
# Posture rule:
#   - cycle_end_tag empty (default today) -> advisory; exit 0.
#   - observed_consecutive_nightly_successes <
#     required_consecutive_nightly_successes -> advisory; exit 0.
#   - cycle_end_tag non-empty and the required nightly evidence streak is
#     present -> blocking; exit 1 when outcomes.json reports a caught-mutant
#     ratio below activation_threshold_percent_per_crate when present, else
#     target_catch_ratio_percent.
#
# Environment:
#   MUTANTS_PACKAGE     : crate name being scored (informational).
#   MUTANTS_OUTPUT_DIR  : directory holding cargo-mutants outcomes.json
#                         (informational; reserved for the catch-ratio
#                         threshold check).
#   MUTANTS_EXIT        : exit code from the cargo-mutants step
#                         (0 = clean, non-zero = survivors).
#   MUTANTS_GATE_OVERRIDE_REASON
#                       : optional escape hatch. When set to a non-empty
#                         string, a blocking-fail verdict is
#                         downgraded to a loud advisory pass: the script
#                         emits a `WARN mutants-gate-override` line on
#                         stderr, appends an audit row to
#                         docs/fuzzing/mutants-overrides.log (timestamp,
#                         package, exit code, cycle_end_tag, reason) and
#                         exits 0. Empty/unset = no override (default).
#                         The corresponding title-based override path is a
#                         PR whose title includes `mutants-gate-override`
#                         and clears
#                         cycle_end_tag in releases.toml; CODEOWNERS gates
#                         that PR on principal-engineer review.
#   MUTANTS_NO_DIFF / CHIO_MUTANTS_NO_DIFF
#                       : explicit no-diff mode for blocking PR lanes where
#                         cargo-mutants was intentionally scoped to an empty
#                         diff. Missing or zero-scoreable outcomes pass only
#                         when one of these is set to 1 and MUTANTS_EXIT=0.
#   MUTANTS_MIN_SCOREABLE
#                       : minimum number of scoreable mutants required in
#                         blocking mode unless explicit no-diff mode is set.
#                         Defaults to 1.
#   CHIO_RELEASES_TOML  : optional path to a releases.toml fixture.
#
# Exit codes:
#   0 advisory pass (or blocking pass when caught ratio meets target, or
#     blocking-fail downgraded by MUTANTS_GATE_OVERRIDE_REASON)
#   1 blocking fail (cycle_end_tag non-empty AND caught ratio below target AND
#     no override reason supplied)
#
# This script is invoked by .github/workflows/mutants.yml's mutants-pr
# and mutants-nightly jobs. It is also safe to run locally:
#
#   MUTANTS_EXIT=0 bash scripts/mutants-gate.sh
#
# Today releases.toml ships with cycle_end_tag empty and zero observed
# nightly successes, so this script exits 0. The evidence-gated
# release-binaries activation starts enforcing without a workflow edit only
# after releases.toml records the two-consecutive-nightly >= 80 percent
# evidence streak and the release PR writes cycle_end_tag. D08 honest-floor
# activation records activation_threshold_percent_per_crate separately from
# the 80 percent target.

set -euo pipefail

PACKAGE="${MUTANTS_PACKAGE:-unknown}"
OUTPUT_DIR="${MUTANTS_OUTPUT_DIR:-}"
EXIT_CODE="${MUTANTS_EXIT:-0}"
OVERRIDE_REASON="${MUTANTS_GATE_OVERRIDE_REASON:-}"
NO_DIFF_MODE="${MUTANTS_NO_DIFF:-${CHIO_MUTANTS_NO_DIFF:-0}}"
MIN_SCOREABLE="${MUTANTS_MIN_SCOREABLE:-1}"

# Locate releases.toml relative to the script. The script lives in
# scripts/ at the repo root, so releases.toml sits one directory up.
script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
releases_toml="${CHIO_RELEASES_TOML:-${repo_root}/releases.toml}"

if [[ ! -f "${releases_toml}" ]]; then
    printf 'mutants-gate: releases.toml missing at %s; defaulting to advisory\n' \
        "${releases_toml}" >&2
    printf 'mutants-gate: package=%s exit=%s posture=advisory verdict=pass\n' \
        "${PACKAGE}" "${EXIT_CODE}"
    exit 0
fi

read_toml_scalar() {
    local key="$1"
    local line trimmed name value
    while IFS= read -r line; do
        # Strip leading and trailing whitespace.
        trimmed="${line#"${line%%[![:space:]]*}"}"
        trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
        [[ "${trimmed}" == *=* ]] || continue

        name="${trimmed%%=*}"
        name="${name%"${name##*[![:space:]]}"}"
        if [[ "${name}" != "${key}" ]]; then
            continue
        fi

        value="${trimmed#*=}"
        value="${value%%#*}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        value="${value#\"}"
        value="${value%\"}"
        printf '%s\n' "${value}"
        return 0
    done < "${releases_toml}"
    return 0
}

cycle_end_tag="$(read_toml_scalar cycle_end_tag)"
target_percent="$(read_toml_scalar target_catch_ratio_percent)"
activation_threshold_percent="$(read_toml_scalar activation_threshold_percent_per_crate)"
required_successes="$(read_toml_scalar required_consecutive_nightly_successes)"
observed_successes="$(read_toml_scalar observed_consecutive_nightly_successes)"

target_percent="${target_percent:-80}"
threshold_percent="${activation_threshold_percent:-${target_percent}}"
required_successes="${required_successes:-2}"
observed_successes="${observed_successes:-0}"

if [[ ! "${target_percent}" =~ ^[0-9]+$ ]]; then
    printf 'mutants-gate: invalid target_catch_ratio_percent=%s in releases.toml\n' \
        "${target_percent}" >&2
    exit 2
fi
if [[ ! "${threshold_percent}" =~ ^[0-9]+$ ]]; then
    printf 'mutants-gate: invalid activation_threshold_percent_per_crate=%s in releases.toml\n' \
        "${threshold_percent}" >&2
    exit 2
fi
if [[ ! "${required_successes}" =~ ^[0-9]+$ ]]; then
    printf 'mutants-gate: invalid required_consecutive_nightly_successes=%s in releases.toml\n' \
        "${required_successes}" >&2
    exit 2
fi
if [[ ! "${observed_successes}" =~ ^[0-9]+$ ]]; then
    printf 'mutants-gate: invalid observed_consecutive_nightly_successes=%s in releases.toml\n' \
        "${observed_successes}" >&2
    exit 2
fi
if [[ ! "${NO_DIFF_MODE}" =~ ^(0|1)$ ]]; then
    printf 'mutants-gate: invalid MUTANTS_NO_DIFF/CHIO_MUTANTS_NO_DIFF=%s; expected 0 or 1\n' \
        "${NO_DIFF_MODE}" >&2
    exit 2
fi
if [[ ! "${MIN_SCOREABLE}" =~ ^[0-9]+$ ]]; then
    printf 'mutants-gate: invalid MUTANTS_MIN_SCOREABLE=%s; expected integer\n' \
        "${MIN_SCOREABLE}" >&2
    exit 2
fi

if [[ -z "${cycle_end_tag}" ]]; then
    printf 'mutants-gate: package=%s exit=%s posture=advisory verdict=pass (cycle_end_tag empty; target=%s%% activation_threshold=%s%% observed_nightly_successes=%s/%s)\n' \
        "${PACKAGE}" "${EXIT_CODE}" "${target_percent}" "${threshold_percent}" "${observed_successes}" "${required_successes}"
    exit 0
fi

if (( observed_successes < required_successes )); then
    printf 'mutants-gate: package=%s exit=%s posture=advisory verdict=pass (nightly evidence pending: target=%s%% activation_threshold=%s%% observed_nightly_successes=%s/%s cycle_end_tag=%s)\n' \
        "${PACKAGE}" "${EXIT_CODE}" "${target_percent}" "${threshold_percent}" "${observed_successes}" "${required_successes}" "${cycle_end_tag}"
    exit 0
fi

outcomes_json=""
if [[ -n "${OUTPUT_DIR}" ]]; then
    for candidate in \
        "${OUTPUT_DIR}/outcomes.json" \
        "${OUTPUT_DIR}/mutants.out/outcomes.json"; do
        if [[ -f "${candidate}" ]]; then
            outcomes_json="${candidate}"
            break
        fi
    done
fi

if [[ ! "${EXIT_CODE}" =~ ^[0-9]+$ ]]; then
    printf 'mutants-gate: invalid MUTANTS_EXIT=%s; expected integer\n' \
        "${EXIT_CODE}" >&2
    exit 2
fi

# Blocking posture: cycle_end_tag is set. cargo-mutants uses a non-zero exit
# when survivors remain, but this lane gates on the configured activation
# threshold rather than requiring every mutant to be caught.
if [[ -f "${outcomes_json}" ]]; then
    if ! command -v jq >/dev/null 2>&1; then
        printf 'mutants-gate: jq is required to score %s\n' "${outcomes_json}" >&2
        exit 2
    fi
    counts="$(jq -r '
        def outcomes:
            (
                if (.outcomes | type) == "array" then .outcomes
                elif (.outcomes | type) == "object" then [.outcomes[]]
                elif type == "array" then .
                else []
                end
            ) | map(select((.scenario? // "") != "Baseline"));
        outcomes as $outcomes
        | [
            ($outcomes | length),
            ($outcomes | map(select((.summary // .status) == "CaughtMutant")) | length),
            ($outcomes | map(select((.summary // .status) == "Unviable")) | length)
          ]
        | @tsv
    ' "${outcomes_json}")"
    total="${counts%%$'\t'*}"
    rest="${counts#*$'\t'}"
    caught="${rest%%$'\t'*}"
    unviable="${rest#*$'\t'}"
    if [[ ! "${total}" =~ ^[0-9]+$ || ! "${caught}" =~ ^[0-9]+$ || ! "${unviable}" =~ ^[0-9]+$ ]]; then
        printf 'mutants-gate: invalid outcomes counts from %s: total=%s caught=%s unviable=%s\n' \
            "${outcomes_json}" "${total}" "${caught}" "${unviable}" >&2
        exit 2
    fi
    scoreable=$(( total - unviable ))
    if (( scoreable < 0 )); then
        printf 'mutants-gate: invalid outcomes counts from %s: total=%s unviable=%s\n' \
            "${outcomes_json}" "${total}" "${unviable}" >&2
        exit 2
    fi

    if (( scoreable < MIN_SCOREABLE )); then
        if [[ "${NO_DIFF_MODE}" == "1" && "${EXIT_CODE}" == "0" ]]; then
            printf 'mutants-gate: package=%s exit=0 posture=blocking verdict=pass-no-diff (cycle_end_tag=%s target=%s%% activation_threshold=%s%% scoreable=%s min_scoreable=%s total=%s unviable=%s)\n' \
                "${PACKAGE}" "${cycle_end_tag}" "${target_percent}" "${threshold_percent}" "${scoreable}" "${MIN_SCOREABLE}" "${total}" "${unviable}"
            exit 0
        fi
        printf 'mutants-gate: package=%s exit=%s posture=blocking verdict=fail (cycle_end_tag=%s target=%s%% activation_threshold=%s%% scoreable=%s min_scoreable=%s total=%s unviable=%s; refusing empty or partial outcomes without explicit no-diff mode)\n' \
            "${PACKAGE}" "${EXIT_CODE}" "${cycle_end_tag}" "${target_percent}" "${threshold_percent}" "${scoreable}" "${MIN_SCOREABLE}" "${total}" "${unviable}" >&2
    elif (( caught * 100 >= threshold_percent * scoreable )); then
        pct_x10=$(( caught * 1000 / scoreable ))
        printf 'mutants-gate: package=%s exit=%s posture=blocking verdict=pass (cycle_end_tag=%s target=%s%% activation_threshold=%s%% caught_ratio=%s.%s%% caught=%s scoreable=%s total=%s unviable=%s observed_nightly_successes=%s/%s)\n' \
            "${PACKAGE}" "${EXIT_CODE}" "${cycle_end_tag}" "${target_percent}" "${threshold_percent}" \
            "$(( pct_x10 / 10 ))" "$(( pct_x10 % 10 ))" "${caught}" "${scoreable}" "${total}" "${unviable}" \
            "${observed_successes}" "${required_successes}"
        exit 0
    else
        pct_x10=$(( caught * 1000 / scoreable ))
        printf 'mutants-gate: package=%s exit=%s posture=blocking verdict=fail (cycle_end_tag=%s target=%s%% activation_threshold=%s%% caught_ratio=%s.%s%% caught=%s scoreable=%s total=%s unviable=%s observed_nightly_successes=%s/%s)\n' \
            "${PACKAGE}" "${EXIT_CODE}" "${cycle_end_tag}" "${target_percent}" "${threshold_percent}" \
            "$(( pct_x10 / 10 ))" "$(( pct_x10 % 10 ))" "${caught}" "${scoreable}" "${total}" "${unviable}" \
            "${observed_successes}" "${required_successes}" >&2
    fi
elif [[ "${NO_DIFF_MODE}" == "1" && "${EXIT_CODE}" == "0" ]]; then
    printf 'mutants-gate: package=%s exit=0 posture=blocking verdict=pass-no-diff (cycle_end_tag=%s target=%s%% activation_threshold=%s%% outcomes_json=missing explicit_no_diff=1)\n' \
        "${PACKAGE}" "${cycle_end_tag}" "${target_percent}" "${threshold_percent}"
    exit 0
elif (( EXIT_CODE == 0 )); then
    printf 'mutants-gate: package=%s exit=0 posture=blocking verdict=fail (cycle_end_tag=%s target=%s%% activation_threshold=%s%% outcomes_json=missing; refusing to trust cargo-mutants success without score data)\n' \
        "${PACKAGE}" "${cycle_end_tag}" "${target_percent}" "${threshold_percent}" >&2
else
    printf 'mutants-gate: package=%s exit=%s posture=blocking verdict=fail (cycle_end_tag=%s target=%s%% activation_threshold=%s%% outcomes_json=missing)\n' \
        "${PACKAGE}" "${EXIT_CODE}" "${cycle_end_tag}" "${target_percent}" "${threshold_percent}" >&2
fi

printf 'mutants-gate: package=%s exit=%s posture=blocking verdict=fail (cycle_end_tag=%s target=%s%% activation_threshold=%s%% observed_nightly_successes=%s/%s)\n' \
    "${PACKAGE}" "${EXIT_CODE}" "${cycle_end_tag}" "${target_percent}" "${threshold_percent}" "${observed_successes}" "${required_successes}" >&2
if [[ -n "${OUTPUT_DIR}" && -d "${OUTPUT_DIR}" ]]; then
    printf 'mutants-gate: see %s for outcomes.json detail\n' "${OUTPUT_DIR}" >&2
fi

# MUTANTS_GATE_OVERRIDE_REASON downgrades a blocking fail to a loud advisory
# pass and appends an audit row. The corresponding permanent path is a PR
# whose title includes `mutants-gate-override` and clears cycle_end_tag in
# releases.toml; CODEOWNERS gates that PR on principal engineer review. The
# env-var path here exists for in-flight CI runs where waiting on a
# CODEOWNERS-reviewed PR is not feasible (e.g. a release-train hot-fix).
# Either path leaves an audit trail.
if [[ -n "${OVERRIDE_REASON}" ]]; then
    audit_log="${repo_root}/docs/fuzzing/mutants-overrides.log"
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # Sanitize the reason: collapse newlines/tabs to single spaces so the
    # audit row stays on one line. Pipe character is reserved as the field
    # separator; replace any embedded pipes with a slash.
    reason_clean="${OVERRIDE_REASON//$'\n'/ }"
    reason_clean="${reason_clean//$'\t'/ }"
    reason_clean="${reason_clean//|/\/}"
    actor="${GITHUB_ACTOR:-${USER:-unknown}}"
    if [[ -f "${audit_log}" ]]; then
        printf '%s | package=%s | exit=%s | cycle_end_tag=%s | actor=%s | reason=%s\n' \
            "${timestamp}" "${PACKAGE}" "${EXIT_CODE}" "${cycle_end_tag}" \
            "${actor}" "${reason_clean}" >> "${audit_log}"
    else
        printf 'mutants-gate: WARN audit log missing at %s; override not recorded\n' \
            "${audit_log}" >&2
    fi
    printf 'mutants-gate: WARN mutants-gate-override engaged package=%s actor=%s reason=%s\n' \
        "${PACKAGE}" "${actor}" "${reason_clean}" >&2
    printf 'mutants-gate: package=%s exit=%s posture=blocking verdict=override (cycle_end_tag=%s)\n' \
        "${PACKAGE}" "${EXIT_CODE}" "${cycle_end_tag}"
    exit 0
fi

exit 1
