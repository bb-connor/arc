#!/usr/bin/env bash
# check-fuzz-budget.sh - Budget gate for GitHub Actions fuzz runner minutes.
#
# Sums the runner-executed time of every job in the cflite_pr.yml,
# cflite_batch.yml, fuzz.yml, mutants.yml, mutants-fuzz-cocoverage.yml, and
# proof-mutants.yml workflows across the last 30 days. A job counts from the
# moment a runner picks it up until it completes; time spent waiting in the
# queue, and jobs that never received a runner, consume no runner minutes and
# are not counted. Jobs still running count up to the current time. Matrix
# jobs that run in parallel each count in full.
#
# cap_mode defaults to "fail" so exceeding the cap hard-halts; set
# GH_FUZZ_BUDGET_CAP_MODE=warn only for ad hoc budget reports.
#
# Usage:
#   scripts/check-fuzz-budget.sh                      # default repo: backbay-labs/chio
#   scripts/check-fuzz-budget.sh OWNER/REPO
#   GH_FUZZ_BUDGET_MINUTES=900 scripts/check-fuzz-budget.sh    # override cap
#   GH_FUZZ_BUDGET_WORKFLOWS=cflite_pr.yml,fuzz.yml scripts/check-fuzz-budget.sh
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
#   0  budget OK
#   1  budget exceeded (sum >= cap)
#   2  precondition failure (gh missing, jq missing, API error, truncated
#      run listing)
#
# Requires: gh, jq

set -euo pipefail

err() { printf '%s\n' "$*" >&2; }

REPO="${1:-backbay-labs/chio}"
CAP_MINUTES="${GH_FUZZ_BUDGET_MINUTES:-1800}"
WINDOW_DAYS=30
# GitHub stops returning results after the first 1000 matches of a filtered
# workflow-run listing. Windows larger than that are listed one day at a time.
LISTING_RESULT_LIMIT=1000
LEDGER="${GH_FUZZ_BUDGET_LEDGER:-}"
if [[ -n "${GH_FUZZ_BUDGET_WORKFLOWS:-}" ]]; then
    IFS=',' read -r -a WORKFLOWS <<<"${GH_FUZZ_BUDGET_WORKFLOWS}"
else
    WORKFLOWS=(
        "cflite_pr.yml"
        "cflite_batch.yml"
        "fuzz.yml"
        "mutants.yml"
        "mutants-fuzz-cocoverage.yml"
        "proof-mutants.yml"
    )
fi
if [[ "${#WORKFLOWS[@]}" -eq 0 ]]; then
    err "fuzz-budget: GH_FUZZ_BUDGET_WORKFLOWS selected no workflows"
    exit 2
fi
if ! [[ "${CAP_MINUTES}" =~ ^[1-9][0-9]*$ ]]; then
    err "fuzz-budget: GH_FUZZ_BUDGET_MINUTES must be a positive integer: ${CAP_MINUTES}"
    exit 2
fi

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
    Darwin) iso_utc() { date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ; } ;;
    Linux)  iso_utc() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; } ;;
    *)      err "unsupported platform: $(uname -s)"; exit 2 ;;
esac
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

total_seconds=0
for wf in "${WORKFLOWS[@]}"; do
    runs="${work}/runs-${wf}.ndjson"
    status=0
    list_runs "${wf}" "${since}" "" "${runs}" || status=$?
    if [[ "${status}" -eq 5 ]]; then
        : >"${runs}"
        slice_start="${since_epoch}"
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
    while IFS=$'\t' read -r run_id attempt run_status created; do
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
            if ! run_seconds="$(jq -s --argjson now "${now_epoch}" \
                '[.[].jobs[]?
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
    done < <(jq -rs 'unique_by(.id) | .[]
        | [.id, (.run_attempt // 1), .status, .created_at] | @tsv' "${runs}")
    if [[ "${workflow_seconds}" -lt 0 ]]; then
        continue
    fi
    printf 'fuzz-budget: workflow=%s runs=%d queried=%d executed=%d min\n' \
        "${wf}" "${run_count}" "${queried}" "$(( (workflow_seconds + 59) / 60 ))"
    total_seconds=$(( total_seconds + workflow_seconds ))
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

total_minutes=$(( (total_seconds + 59) / 60 ))
remaining=$(( CAP_MINUTES - total_minutes ))

printf 'fuzz-budget: window=%s days, used=%d min, cap=%d min, remaining=%d min\n' \
    "${WINDOW_DAYS}" "${total_minutes}" "${CAP_MINUTES}" "${remaining}"

if (( total_minutes >= CAP_MINUTES )); then
    err "fuzz-budget: HALT - used ${total_minutes} min >= cap ${CAP_MINUTES} min in last ${WINDOW_DAYS} days"
    if [[ "${cap_mode}" == "warn" ]]; then
        err "fuzz-budget: continuing because GH_FUZZ_BUDGET_CAP_MODE=warn"
        exit 0
    fi
    exit 1
fi
exit 0
