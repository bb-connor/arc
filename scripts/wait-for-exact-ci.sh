#!/usr/bin/env bash
set -euo pipefail

repository="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
candidate_sha="${GITHUB_SHA:?GITHUB_SHA is required}"
wait_seconds="${CHIO_EXACT_CI_WAIT_SECONDS:-21600}"
poll_seconds="${CHIO_EXACT_CI_POLL_SECONDS:-30}"
dispatch_attempted=false

if [[ ! "${wait_seconds}" =~ ^[1-9][0-9]*$ ]]; then
  echo "CHIO_EXACT_CI_WAIT_SECONDS must be a positive integer" >&2
  exit 1
fi
if [[ ! "${poll_seconds}" =~ ^[1-9][0-9]*$ ]]; then
  echo "CHIO_EXACT_CI_POLL_SECONDS must be a positive integer" >&2
  exit 1
fi

deadline=$((SECONDS + wait_seconds))
while (( SECONDS < deadline )); do
  run="$({
    gh api --method GET \
      "repos/${repository}/actions/workflows/ci.yml/runs" \
      -f "head_sha=${candidate_sha}" \
      -f per_page=100 \
      --jq '
        [.workflow_runs[]
          | select(.head_sha == "'"${candidate_sha}"'")
          | select(.event == "push" or .event == "workflow_dispatch")]
        | sort_by(.created_at)
        | reverse
        | .[0]
        | if . == null then ""
          else [.status, (.conclusion // ""), (.id | tostring), .html_url]
          | @tsv
          end
      '
  } || {
    echo "failed to query exact-SHA CI state" >&2
    exit 1
  })"

  if [[ -z "${run}" ]]; then
    if [[ "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" && "${dispatch_attempted}" == "false" ]]; then
      ref_name="${GITHUB_REF_NAME:?GITHUB_REF_NAME is required for manual exact CI}"
      regression_deletion_evidence="$({
        gh api --method GET "repos/${repository}/commits/${candidate_sha}/pulls" |
          jq -r --arg candidate "${candidate_sha}" \
            '[.[] | select(.state == "open" and .head.sha == $candidate) | (.body // "")] | first // ""'
      } || {
        echo "failed to query exact-head PR evidence" >&2
        exit 1
      })"
      echo "dispatching CI for manual qualification ref ${ref_name}"
      gh workflow run ci.yml --repo "${repository}" --ref "${ref_name}" \
        -f "regression_deletion_evidence=${regression_deletion_evidence}"
      dispatch_attempted=true
    fi
    echo "waiting for CI to start for ${candidate_sha}"
    sleep "${poll_seconds}"
    continue
  fi

  IFS=$'\t' read -r status conclusion run_id run_url <<<"${run}"
  if [[ "${status}" != "completed" ]]; then
    echo "waiting for exact-SHA CI run ${run_id}: ${status}"
    sleep "${poll_seconds}"
    continue
  fi
  if [[ "${conclusion}" != "success" ]]; then
    echo "exact-SHA CI run ${run_id} concluded ${conclusion}: ${run_url}" >&2
    exit 1
  fi

  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'run_id=%s\nrun_url=%s\n' "${run_id}" "${run_url}" >>"${GITHUB_OUTPUT}"
  fi
  echo "exact-SHA CI succeeded: ${run_url}"
  exit 0
done

echo "timed out waiting for CI on exact candidate ${candidate_sha}" >&2
exit 1
