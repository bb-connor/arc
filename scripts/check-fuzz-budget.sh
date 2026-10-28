#!/usr/bin/env bash
# check-fuzz-budget.sh - Budget gate for GitHub Actions fuzz runner minutes.
#
# Measures the runner-executed time of every job across the last 30 days, per
# budget envelope:
#
#   cflite    cflite_pr.yml, cflite_batch.yml        cap  1,800 min
#   native    fuzz.yml                               cap 26,000 min
#   mutation  mutants.yml, mutants-fuzz-cocoverage.yml,
#             proof-mutants.yml                      reported, not capped
#
# The cflite envelope's window starts at the later of 30 days ago and the
# UTC timestamp in fuzz/cflite-budget-epoch (one line, YYYY-MM-DDTHH:MM:SSZ).
# A missing, malformed or future epoch fails the cflite envelope closed.
#
# A job counts from the moment a runner picks it up until it completes; time
# spent waiting in the queue, and jobs that never received a runner, consume
# no runner minutes and are not counted. Jobs still running count up to the
# current time. Matrix jobs that run in parallel each count in full.
#
# A capped envelope at or over its cap fails the gate, and an API error,
# truncated listing or unregistered workflow in a capped envelope fails it
# closed. The mutation envelope only reports: its usage, or the reason it is
# unverified, is printed and never changes the exit code. cap_mode defaults to
# "fail"; set GH_FUZZ_BUDGET_CAP_MODE=warn only for advisory lanes.
#
# Usage:
#   scripts/check-fuzz-budget.sh                      # default repo: backbay-labs/chio
#   scripts/check-fuzz-budget.sh OWNER/REPO
#   GH_FUZZ_BUDGET_SCOPE=cflite scripts/check-fuzz-budget.sh   # cflite|native|mutation|all
#   GH_FUZZ_BUDGET_LEDGER=/path/ledger.json scripts/check-fuzz-budget.sh
#   GH_FUZZ_BUDGET_RATE_LIMIT_MODE=warn scripts/check-fuzz-budget.sh
#   GH_FUZZ_BUDGET_MISSING_WORKFLOW_MODE=warn scripts/check-fuzz-budget.sh
#   GH_FUZZ_BUDGET_CAP_MODE=warn scripts/check-fuzz-budget.sh
#
# GH_FUZZ_BUDGET_LEDGER names a JSON file that caches the executed seconds of
# completed run attempts, so repeated invocations only query jobs for runs the
# ledger has not seen. Invocations that measure different workflows can share
# one ledger. The file is rewritten without entries for runs created before the
# window. An unreadable or foreign ledger is discarded and every run is
# queried again.
#
# Exit codes:
#   0  every measured capped envelope is under its cap
#   1  a capped envelope is at or over its cap
#   2  precondition failure in a capped envelope (gh missing, jq missing, API
#      error, truncated run listing, unknown scope)
#
# Requires: gh, jq

set -euo pipefail

err() { printf '%s\n' "$*" >&2; }

REPO="${1:-backbay-labs/chio}"
WINDOW_DAYS=30
# GitHub stops returning results after the first 1000 matches of a filtered
# workflow-run listing. Windows larger than that are listed one day at a time.
LISTING_RESULT_LIMIT=1000
LEDGER="${GH_FUZZ_BUDGET_LEDGER:-}"
SCOPE="${GH_FUZZ_BUDGET_SCOPE:-all}"

CFLITE_WORKFLOWS=("cflite_pr.yml" "cflite_batch.yml")
CFLITE_CAP_MINUTES=1800
NATIVE_WORKFLOWS=("fuzz.yml")
NATIVE_CAP_MINUTES=26000
MUTATION_WORKFLOWS=("mutants.yml" "mutants-fuzz-cocoverage.yml" "proof-mutants.yml")

case "${SCOPE}" in
    cflite) ENVELOPES=(cflite) ;;
    native) ENVELOPES=(native) ;;
    mutation) ENVELOPES=(mutation) ;;
    all) ENVELOPES=(cflite native mutation) ;;
    *)
        err "fuzz-budget: unknown GH_FUZZ_BUDGET_SCOPE: ${SCOPE} (cflite|native|mutation|all)"
        exit 2
        ;;
esac

require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "missing required tool: $1"
        exit 2
    fi
}

require gh
require jq
require date

rate_limit_mode="${GH_FUZZ_BUDGET_RATE_LIMIT_MODE:-fail}"
missing_workflow_mode="${GH_FUZZ_BUDGET_MISSING_WORKFLOW_MODE:-fail}"
cap_mode="${GH_FUZZ_BUDGET_CAP_MODE:-fail}"

now_epoch="$(date -u +%s)"
since_epoch=$(( now_epoch - WINDOW_DAYS * 86400 ))
case "$(uname -s)" in
    Darwin)
        iso_utc() { date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ; }
        utc_epoch() { date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$1" +%s 2>/dev/null; }
        ;;
    Linux)
        iso_utc() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }
        utc_epoch() { date -u -d "$1" +%s 2>/dev/null; }
        ;;
    *)      err "unsupported platform: $(uname -s)"; exit 2 ;;
esac

CFLITE_EPOCH_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/fuzz/cflite-budget-epoch"

# cflite_window_start: prints the cflite envelope's window start in epoch
# seconds, or exits 2 when the epoch file is unusable.
cflite_window_start() {
    local text epoch
    if [[ ! -f "${CFLITE_EPOCH_FILE}" ]]; then
        err "fuzz-budget: cflite budget epoch ${CFLITE_EPOCH_FILE} is missing"
        exit 2
    fi
    text="$(cat "${CFLITE_EPOCH_FILE}")"
    if ! [[ "${text}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
        || ! epoch="$(utc_epoch "${text}")" \
        || [[ "$(iso_utc "${epoch}")" != "${text}" ]]; then
        err "fuzz-budget: cflite budget epoch in ${CFLITE_EPOCH_FILE} is not one UTC timestamp: ${text}"
        exit 2
    fi
    if (( epoch > now_epoch )); then
        err "fuzz-budget: cflite budget epoch ${text} is in the future"
        exit 2
    fi
    if (( epoch > since_epoch )); then
        printf '%d\n' "${epoch}"
    else
        printf '%d\n' "${since_epoch}"
    fi
}
since="$(iso_utc "${since_epoch}")"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

ledger_in="${work}/ledger-in.json"
printf '{}' >"${ledger_in}"
if [[ -n "${LEDGER}" && -s "${LEDGER}" ]]; then
    if jq -e --arg repo "${REPO}" \
        '.repo == $repo and (.runs | type == "object")
         and ([.runs[] | (.seconds | type == "number" and . >= 0)
               and (.created | type == "string")] | all)' \
        "${LEDGER}" >/dev/null 2>&1; then
        jq '.runs' "${LEDGER}" >"${ledger_in}"
    else
        err "fuzz-budget: ignoring unusable ledger ${LEDGER}; querying every run"
    fi
fi
ledger_out="${work}/ledger-out.ndjson"
: >"${ledger_out}"

# api_get PATH OUTPUT_FILE: paginated GET. Returns 0 on success, 3 when the
# API reports a missing resource, 4 when rate limited, and exits 2 otherwise.
api_get() {
    local path="$1" output="$2" api_error="${work}/api-error"
    if gh api --paginate "${path}" >"${output}" 2>"${api_error}"; then
        return 0
    fi
    local error_text
    error_text="$(cat "${api_error}")"
    if grep -Eq 'HTTP 404|Not Found' <<<"${error_text}"; then
        return 3
    fi
    if grep -Eiq 'rate limit exceeded|HTTP 403' <<<"${error_text}"; then
        return 4
    fi
    err "fuzz-budget: GitHub API failed for ${path}: ${error_text}"
    exit 2
}

rate_limited() {
    err "fuzz-budget: GitHub API rate limited while checking $1; budget usage is unverified"
    if [[ "${rate_limit_mode}" == "warn" ]]; then
        err "fuzz-budget: continuing because GH_FUZZ_BUDGET_RATE_LIMIT_MODE=warn"
        return 0
    fi
    exit 2
}

# list_runs WORKFLOW FROM_ISO TO_ISO OUTPUT_FILE: writes one run per line.
# TO_ISO may be empty for an open-ended range. Returns api_get's status.
list_runs() {
    local wf="$1" from="$2" to="$3" output="$4" range pages="${work}/pages.json"
    if [[ -n "${to}" ]]; then
        range="${from}..${to}"
    else
        range=">=${from}"
    fi
    local status=0
    api_get "repos/${REPO}/actions/workflows/${wf}/runs?created=${range}&per_page=100" \
        "${pages}" || status=$?
    if [[ "${status}" -ne 0 ]]; then
        return "${status}"
    fi
    if [[ ! -s "${pages}" ]]; then
        err "fuzz-budget: GitHub API returned an empty runs payload for ${wf}"
        exit 2
    fi
    local total listed
    if ! total="$(jq -s '.[0].total_count' "${pages}")" \
        || ! [[ "${total}" =~ ^[0-9]+$ ]]; then
        err "fuzz-budget: failed to parse workflow runs for ${wf}"
        exit 2
    fi
    if ! jq -c '.workflow_runs[]?' "${pages}" >"${output}"; then
        err "fuzz-budget: failed to parse workflow runs for ${wf}"
        exit 2
    fi
    listed="$(jq -s 'map(.id) | unique | length' "${output}")"
    if (( total > LISTING_RESULT_LIMIT )); then
        return 5
    fi
    if (( listed < total )); then
        err "fuzz-budget: ${wf} listing for ${range} returned ${listed} of ${total} runs"
        exit 2
    fi
    return 0
}

# measure_workflows OUTPUT_FILE WINDOW_START WORKFLOW...: writes the summed
# runner seconds of runs created at or after WINDOW_START (epoch seconds).
measure_workflows() {
    local output="$1" window_epoch="$2" window total_seconds=0
    shift 2
    window="$(iso_utc "${window_epoch}")"
    for wf in "$@"; do
        runs="${work}/runs-${wf}.ndjson"
        status=0
        list_runs "${wf}" "${window}" "" "${runs}" || status=$?
        if [[ "${status}" -eq 5 ]]; then
            : >"${runs}"
            slice_start="${window_epoch}"
            while (( slice_start < now_epoch )); do
                slice_end=$(( slice_start + 86400 ))
                slice="${work}/slice.ndjson"
                status=0
                list_runs "${wf}" "$(iso_utc "${slice_start}")" "$(iso_utc "${slice_end}")" \
                    "${slice}" || status=$?
                if [[ "${status}" -eq 5 ]]; then
                    err "fuzz-budget: ${wf} has more than ${LISTING_RESULT_LIMIT} runs in one day starting $(iso_utc "${slice_start}"); budget usage is unverified"
                    exit 2
                fi
                if [[ "${status}" -ne 0 ]]; then
                    break
                fi
                cat "${slice}" >>"${runs}"
                slice_start="${slice_end}"
            done
        fi
        if [[ "${status}" -eq 3 ]]; then
            err "fuzz-budget: workflow ${wf} is not registered; budget usage is unverified"
            if [[ "${missing_workflow_mode}" == "warn" ]]; then
                err "fuzz-budget: continuing because GH_FUZZ_BUDGET_MISSING_WORKFLOW_MODE=warn"
                continue
            fi
            exit 2
        fi
        if [[ "${status}" -eq 4 ]]; then
            rate_limited "${wf}"
            continue
        fi

        workflow_seconds=0
        run_count=0
        queried=0
        while IFS=$'\t' read -r run_id attempt run_status created conclusion; do
            run_count=$(( run_count + 1 ))
            key="${run_id}:${attempt}"
            cached="$(jq -r --arg key "${key}" '.[$key].seconds // empty' "${ledger_in}")"
            if [[ -n "${cached}" ]]; then
                run_seconds="${cached}"
            else
                jobs="${work}/jobs.json"
                status=0
                api_get "repos/${REPO}/actions/runs/${run_id}/jobs?filter=all&per_page=100" \
                    "${jobs}" || status=$?
                if [[ "${status}" -eq 4 ]]; then
                    rate_limited "${wf}"
                    workflow_seconds=-1
                    break
                fi
                if [[ "${status}" -ne 0 ]]; then
                    err "fuzz-budget: jobs for ${wf} run ${run_id} are missing"
                    exit 2
                fi
                queried=$(( queried + 1 ))
                # Every page must be a jobs envelope with the same numeric
                # total_count, and the unique job ids across pages must
                # account for all of them before any time is summed or cached.
                if ! listed="$(jq -rs '
                    if length > 0
                       and all(.[]; type == "object"
                           and (.total_count | type) == "number"
                           and (.jobs | type) == "array"
                           and all(.jobs[]; type == "object" and (.id | type) == "number"))
                       and ([.[].total_count] | unique | length) == 1
                    then "\(.[0].total_count) \([.[].jobs[].id] | unique | length)"
                    else "malformed" end' "${jobs}" 2>/dev/null)" \
                    || ! [[ "${listed}" =~ ^([0-9]+)\ ([0-9]+)$ ]]; then
                    err "fuzz-budget: malformed jobs listing for ${wf} run ${run_id}"
                    exit 2
                fi
                declared="${BASH_REMATCH[1]}"
                returned="${BASH_REMATCH[2]}"
                if [[ "${returned}" != "${declared}" ]]; then
                    err "fuzz-budget: jobs listing for ${wf} run ${run_id} returned ${returned} of ${declared} jobs"
                    exit 2
                fi
                # A run cancelled before its jobs were created, or one whose
                # workflow file failed to start, has no jobs and no runner time.
                if [[ "${declared}" == "0" && "${conclusion}" != "cancelled" \
                    && "${conclusion}" != "startup_failure" ]]; then
                    err "fuzz-budget: ${wf} run ${run_id} lists no jobs (conclusion: ${conclusion:-none})"
                    exit 2
                fi
                # Runner time needs the accounting fields of every job. A job
                # assigned to a runner must carry its start (and, once
                # completed, its completion) time. A job never assigned to a
                # runner consumes nothing, which is only consistent with it
                # never running: cancelled, skipped or failed before
                # assignment, or still waiting for a runner.
                if ! violation="$(jq -rs --arg run_status "${run_status}" '
                    def text_or_null: type == "string" or type == "null";
                    [[.[].jobs[]] | unique_by(.id)[]
                     | if ((.status | type) != "string"
                           or ((has("runner_name") and (.runner_name | text_or_null)) | not)
                           or ((has("started_at") and (.started_at | text_or_null)) | not)
                           or ((has("completed_at") and (.completed_at | text_or_null)) | not)
                           or ((has("conclusion") and (.conclusion | text_or_null)) | not))
                       then "job \(.id) lacks accounting fields"
                       elif $run_status == "completed" and .status != "completed"
                       then "completed run lists unfinished job \(.id)"
                       elif (.runner_name // "") != "" then
                         if .started_at == null then "assigned job \(.id) has no start time"
                         elif .status == "completed" and .completed_at == null
                         then "completed job \(.id) has no completion time"
                         else empty end
                       elif .status == "completed"
                            and ([.conclusion] | inside(["cancelled", "skipped", "failure"]) | not)
                       then "unassigned job \(.id) concluded \(.conclusion)"
                       else empty end
                    ] | first // "ok"' "${jobs}" 2>/dev/null)" || [[ -z "${violation}" ]]; then
                    err "fuzz-budget: malformed jobs listing for ${wf} run ${run_id}"
                    exit 2
                fi
                if [[ "${violation}" != "ok" ]]; then
                    err "fuzz-budget: ${wf} run ${run_id}: ${violation}"
                    exit 2
                fi
                if ! run_seconds="$(jq -s --argjson now "${now_epoch}" \
                    '[[.[].jobs[]] | unique_by(.id)[]
                      | select((.runner_name // "") != "" and .started_at != null)
                      | (if .completed_at == null then $now
                         else (.completed_at | fromdateiso8601) end)
                        - (.started_at | fromdateiso8601)
                      | if . < 0 then 0 else . end
                     ] | add // 0 | floor' "${jobs}")" \
                    || ! [[ "${run_seconds}" =~ ^[0-9]+$ ]]; then
                    err "fuzz-budget: failed to parse jobs for ${wf} run ${run_id}"
                    exit 2
                fi
            fi
            if [[ "${run_status}" == "completed" ]]; then
                jq -nc --arg key "${key}" --argjson seconds "${run_seconds}" \
                    --arg created "${created}" \
                    '{key: $key, value: {seconds: $seconds, created: $created}}' \
                    >>"${ledger_out}"
            fi
            workflow_seconds=$(( workflow_seconds + run_seconds ))
        done < <(jq -rs --arg window "${window}" 'unique_by(.id) | .[]
            | select(.created_at >= $window)
            | [.id, (.run_attempt // 1), .status, .created_at, (.conclusion // "")]
            | @tsv' "${runs}")
        if [[ "${workflow_seconds}" -lt 0 ]]; then
            continue
        fi
        printf 'fuzz-budget: workflow=%s runs=%d queried=%d executed=%d min\n' \
            "${wf}" "${run_count}" "${queried}" "$(( (workflow_seconds + 59) / 60 ))"
        total_seconds=$(( total_seconds + workflow_seconds ))
    done
    printf '%d\n' "${total_seconds}" >"${output}"
}

over_cap=0
for envelope in "${ENVELOPES[@]}"; do
    case "${envelope}" in
        cflite) workflows=("${CFLITE_WORKFLOWS[@]}"); cap="${CFLITE_CAP_MINUTES}" ;;
        native) workflows=("${NATIVE_WORKFLOWS[@]}"); cap="${NATIVE_CAP_MINUTES}" ;;
        mutation) workflows=("${MUTATION_WORKFLOWS[@]}"); cap="" ;;
    esac
    measured="${work}/measured-${envelope}"
    window_epoch="${since_epoch}"
    if [[ "${envelope}" == "cflite" ]]; then
        window_epoch="$(cflite_window_start)" || exit 2
    fi
    set +e
    (
        set -e
        measure_workflows "${measured}" "${window_epoch}" "${workflows[@]}"
    )
    status=$?
    set -e
    if [[ "${status}" -ne 0 ]]; then
        if [[ -z "${cap}" ]]; then
            err "fuzz-budget: envelope=${envelope} usage is unverified; reported only, not capped"
            continue
        fi
        exit "${status}"
    fi
    used=$(( ($(cat "${measured}") + 59) / 60 ))
    if [[ -z "${cap}" ]]; then
        printf 'fuzz-budget: envelope=%s window_start=%s, used=%d min, reported only, not capped\n' \
            "${envelope}" "$(iso_utc "${window_epoch}")" "${used}"
        continue
    fi
    printf 'fuzz-budget: envelope=%s window_start=%s, used=%d min, cap=%d min, remaining=%d min\n' \
        "${envelope}" "$(iso_utc "${window_epoch}")" "${used}" "${cap}" "$(( cap - used ))"
    if (( used >= cap )); then
        err "fuzz-budget: HALT - envelope=${envelope} used ${used} min >= cap ${cap} min since $(iso_utc "${window_epoch}")"
        over_cap=1
    fi
done

if [[ -n "${LEDGER}" ]]; then
    ledger_tmp="${LEDGER}.tmp.$$"
    jq -s --arg repo "${REPO}" --arg since "${since}" \
        --slurpfile previous "${ledger_in}" \
        '{repo: $repo,
          runs: (($previous[0]
                  | with_entries(select(.value.created >= $since)))
                 + from_entries)}' "${ledger_out}" >"${ledger_tmp}"
    mv "${ledger_tmp}" "${LEDGER}"
fi

if (( over_cap )); then
    if [[ "${cap_mode}" == "warn" ]]; then
        err "fuzz-budget: continuing because GH_FUZZ_BUDGET_CAP_MODE=warn"
        exit 0
    fi
    exit 1
fi
exit 0
