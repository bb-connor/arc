#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="$(mktemp "${TMPDIR:-/tmp}/chio-active-defense-conformance.XXXXXX")"
observed_file="$(mktemp "${TMPDIR:-/tmp}/chio-active-defense-tests.XXXXXX")"
trap 'rm -f "${output}" "${observed_file}"' EXIT

expected=(
  slow_cumulative_exfiltration
  canary_pre_dispatch_denial
  honey_tool_pre_dispatch_denial
  temporal_within_boundary
  declassification_replay
  session_isolation_epoch
  event_producer_trust
  truncated_lineage_no_containment
  overlapping_ttl_lift
  partial_rollback_truth
)

cd "${repo_root}"
set +e
CARGO_INCREMENTAL=0 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TERM_COLOR=never \
  cargo test -p chio-conformance --test active_defense -- --nocapture \
  2>&1 | tee "${output}"
status=${PIPESTATUS[0]}
set -e
if [[ "${status}" -ne 0 ]]; then
  exit "${status}"
fi

sed -nE 's/^test ([a-z0-9_]+) \.\.\. ok$/\1/p' "${output}" >"${observed_file}"
observed_count="$(wc -l <"${observed_file}" | tr -d '[:space:]')"
if [[ "${observed_count}" -ne "${#expected[@]}" ]]; then
  echo "active-defense conformance executed ${observed_count} passing tests;" \
    "expected exactly ${#expected[@]}" >&2
  exit 1
fi

for test_name in "${expected[@]}"; do
  count="$(grep -Fxc -- "${test_name}" "${observed_file}" || true)"
  if [[ "${count}" -ne 1 ]]; then
    echo "active-defense test ${test_name} executed ${count} times; expected exactly once" >&2
    exit 1
  fi
done

while IFS= read -r test_name; do
  known=0
  for expected_name in "${expected[@]}"; do
    if [[ "${test_name}" == "${expected_name}" ]]; then
      known=1
      break
    fi
  done
  if [[ "${known}" -ne 1 ]]; then
    echo "unexpected active-defense test executed: ${test_name}" >&2
    exit 1
  fi
done <"${observed_file}"

summary_pattern='^test result: ok\. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in [0-9]+([.][0-9]+)?s$'
if [[ "$(grep -Ec -- "${summary_pattern}" "${output}" || true)" -ne 1 ]]; then
  echo "active-defense conformance summary is absent, non-exact, or ambiguous" >&2
  exit 1
fi

echo "Active-defense conformance gate passed with exactly ten release tests"
