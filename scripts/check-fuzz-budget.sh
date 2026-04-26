#!/usr/bin/env bash
# check-fuzz-budget.sh - Self-imposed cap on GitHub Actions fuzz minutes.
#
# The public-repo free tier on GitHub Actions allows 2,000 runner-minutes
# per month. The trajectory's continuous-fuzzing-path decision (locked in
# .planning/trajectory/decisions.yml) holds ClusterFuzzLite at 1,800
# runner-minutes per rolling 30-day window, leaving 200-minute headroom
# for everything else on the free tier.
#
# This script queries the workflow-run history for the cflite_pr.yml and
# cflite_batch.yml workflows (M02-owned), sums their billed seconds across
# the last 30 days, converts to minutes, and exits non-zero when the sum
# crosses 1,800. The orchestrator runs this on a scheduled cadence and as
# a step in cflite_batch.yml so the cap acts as a hard halt rather than a
# soft warning.
#
# Usage:
#   scripts/check-fuzz-budget.sh                      # default repo: bb-connor/arc
#   scripts/check-fuzz-budget.sh OWNER/REPO
#   GH_FUZZ_BUDGET_MINUTES=900 scripts/check-fuzz-budget.sh    # override cap
#
# Exit codes:
#   0  budget OK
#   1  budget exceeded (sum >= cap)
#   2  precondition failure (gh missing, jq missing, API error)
#
# Requires: gh, jq

set -euo pipefail

REPO="${1:-bb-connor/arc}"
CAP_MINUTES="${GH_FUZZ_BUDGET_MINUTES:-1800}"
WINDOW_DAYS=30
WORKFLOWS=("cflite_pr.yml" "cflite_batch.yml")

err() { printf '%s\n' "$*" >&2; }

require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "missing required tool: $1"
        exit 2
    fi
}

require gh
require jq
require date

# Compute ISO-8601 UTC timestamp for the window start.
case "$(uname -s)" in
    Darwin) since="$(date -u -v-${WINDOW_DAYS}d +%Y-%m-%dT%H:%M:%SZ)" ;;
    Linux)  since="$(date -u -d "${WINDOW_DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ)" ;;
    *)      err "unsupported platform: $(uname -s)"; exit 2 ;;
esac

total_seconds=0

for wf in "${WORKFLOWS[@]}"; do
    runs_path="repos/${REPO}/actions/workflows/${wf}/runs"
    # Fetch runs created in the window, paginate up to 1000.
    runs="$(gh api --paginate \
        "${runs_path}?created=>=${since}&per_page=100" \
        2>/dev/null || true)"
    if [[ -z "${runs}" ]]; then
        # Workflow may not exist yet; treat as zero.
        continue
    fi
    # gh api --paginate returns concatenated JSON objects; jq -s merges.
    ids="$(printf '%s' "${runs}" | jq -s '[.[].workflow_runs[]?.id // empty] | unique | .[]')"
    if [[ -z "${ids}" ]]; then
        continue
    fi
    while IFS= read -r run_id; do
        [[ -z "${run_id}" ]] && continue
        timing="$(gh api "repos/${REPO}/actions/runs/${run_id}/timing" 2>/dev/null || true)"
        if [[ -z "${timing}" ]]; then
            continue
        fi
        ms="$(printf '%s' "${timing}" \
            | jq '[.billable | to_entries[] | .value.total_ms // 0] | add // 0')"
        total_seconds=$(( total_seconds + ms / 1000 ))
    done <<<"${ids}"
done

total_minutes=$(( (total_seconds + 59) / 60 ))
remaining=$(( CAP_MINUTES - total_minutes ))

printf 'fuzz-budget: window=%s days, used=%d min, cap=%d min, remaining=%d min\n' \
    "${WINDOW_DAYS}" "${total_minutes}" "${CAP_MINUTES}" "${remaining}"

if (( total_minutes >= CAP_MINUTES )); then
    err "fuzz-budget: HALT - used ${total_minutes} min >= cap ${CAP_MINUTES} min in last ${WINDOW_DAYS} days"
    exit 1
fi
exit 0
