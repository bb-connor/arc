#!/usr/bin/env bash
set -euo pipefail

repository="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
candidate_sha="${GITHUB_SHA:?GITHUB_SHA is required}"
wait_seconds="${CHIO_EXACT_CI_WAIT_SECONDS:-21600}"
poll_seconds="${CHIO_EXACT_CI_POLL_SECONDS:-30}"
dispatch_attempted=false
allow_workflow_dispatch=false

if [[ "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" && "${GITHUB_REF_NAME:-}" != "main" ]]; then
  allow_workflow_dispatch=true
fi

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
          | select(
            .event == "push" or
            (.event == "workflow_dispatch" and '"${allow_workflow_dispatch}"')
          )]
        | sort_by(.created_at)
        | reverse
        | .[0]
        | if . == null then ""
          else [
            .status,
            (.conclusion // "pending"),
            (.id | tostring),
            (.run_attempt | tostring),
            .html_url
          ]
          | @tsv
          end
      '
  } || {
    echo "failed to query exact-SHA CI state" >&2
    exit 1
  })"

  if [[ -z "${run}" ]]; then
    if [[ "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" && "${GITHUB_REF_NAME:-}" == "main" ]]; then
      echo "manual main qualification requires an exact-SHA push CI run" >&2
      exit 1
    fi
    if [[ "${allow_workflow_dispatch}" == "true" && "${dispatch_attempted}" == "false" ]]; then
      ref_name="${GITHUB_REF_NAME:?GITHUB_REF_NAME is required for manual exact CI}"
      encoded_ref="$(jq -rn --arg ref "${ref_name}" '$ref | @uri')"
      ref_sha="$({
        gh api --method GET "repos/${repository}/commits/${encoded_ref}" --jq .sha
      } || {
        echo "failed to resolve manual qualification ref ${ref_name}" >&2
        exit 1
      })"
      if [[ "${ref_sha}" != "${candidate_sha}" ]]; then
        echo "manual qualification ref ${ref_name} moved from ${candidate_sha} to ${ref_sha}" >&2
        exit 1
      fi
      pulls_json="$({
        gh api --method GET "repos/${repository}/commits/${candidate_sha}/pulls"
      } || {
        echo "failed to query exact-head PR evidence" >&2
        exit 1
      })"
      main_pr_count="$({
        jq -r --arg candidate "${candidate_sha}" --arg repository "${repository}" \
          '[.[] | select(
            .state == "open" and
            .head.sha == $candidate and
            .base.ref == "main" and
            .base.repo.full_name == $repository
          )] | length' <<<"${pulls_json}"
      } || {
        echo "failed to select exact-head main PR evidence" >&2
        exit 1
      })"
      if [[ ! "${main_pr_count}" =~ ^[0-9]+$ ]]; then
        echo "invalid exact-head main PR count: ${main_pr_count}" >&2
        exit 1
      fi
      if [[ "${main_pr_count}" -gt 1 ]]; then
        echo "multiple open main PRs share exact head ${candidate_sha}" >&2
        exit 1
      fi
      regression_evidence_pr=""
      if [[ "${main_pr_count}" -eq 1 ]]; then
        regression_evidence_pr="$({
          jq -r --arg candidate "${candidate_sha}" --arg repository "${repository}" \
            '[.[] | select(
              .state == "open" and
              .head.sha == $candidate and
              .base.ref == "main" and
              .base.repo.full_name == $repository
            ) | .number] | first' <<<"${pulls_json}"
        } || {
          echo "failed to read exact-head main PR number" >&2
          exit 1
        })"
      fi
      echo "dispatching CI for manual qualification ref ${ref_name}"
      gh workflow run ci.yml --repo "${repository}" --ref "${ref_name}" \
        -f "regression_evidence_pr=${regression_evidence_pr}"
      dispatch_attempted=true
    fi
    echo "waiting for CI to start for ${candidate_sha}"
    sleep "${poll_seconds}"
    continue
  fi

  IFS=$'\t' read -r status conclusion run_id run_attempt run_url <<<"${run}"
  if [[ "${status}" != "completed" ]]; then
    echo "waiting for exact-SHA CI run ${run_id}: ${status}"
    sleep "${poll_seconds}"
    continue
  fi
  if [[ "${conclusion}" != "success" ]]; then
    echo "exact-SHA CI run ${run_id} concluded ${conclusion}: ${run_url}" >&2
    exit 1
  fi
  if [[ ! "${run_attempt}" =~ ^[1-9][0-9]*$ ]]; then
    echo "exact-SHA CI run ${run_id} has invalid attempt ${run_attempt}" >&2
    exit 1
  fi

  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'run_id=%s\nrun_attempt=%s\nrun_url=%s\n' \
      "${run_id}" \
      "${run_attempt}" \
      "${run_url}" >>"${GITHUB_OUTPUT}"
  fi
  echo "exact-SHA CI succeeded: ${run_url}"
  exit 0
done

echo "timed out waiting for CI on exact candidate ${candidate_sha}" >&2
exit 1
