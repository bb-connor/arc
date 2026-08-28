#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
workflow="${repo_root}/.github/workflows/release-qualification.yml"
qualification="${repo_root}/scripts/qualify-release.sh"
waiter="${repo_root}/scripts/wait-for-exact-ci.sh"

for marker in \
  "Exact-head CI prerequisite" \
  "needs: exact_ci" \
  "run: ./scripts/wait-for-exact-ci.sh" \
  "CHIO_RELEASE_WORKSPACE_GATE_MODE: exact-ci" \
  'CHIO_EXACT_CI_RUN_ID: ${{ needs.exact_ci.outputs.run-id }}' \
  "Release MSRV full-workspace test" \
  "cargo test --workspace"; do
  grep -F "${marker}" "${workflow}" >/dev/null
done

grep -F 'workspace_gate_mode="${CHIO_RELEASE_WORKSPACE_GATE_MODE:-local}"' "${qualification}" >/dev/null
grep -F 'if [[ "${GITHUB_ACTIONS:-}" != "true" ]]' "${qualification}" >/dev/null
grep -F 'exact-ci-run-id.txt' "${qualification}" >/dev/null
grep -F 'actions/workflows/ci.yml/runs' "${waiter}" >/dev/null
grep -F 'select(.event == "push" or .event == "workflow_dispatch")' "${waiter}" >/dev/null
grep -F 'if [[ "${conclusion}" != "success" ]]' "${waiter}" >/dev/null

if grep -F "cargo +1.93.0" "${workflow}" >/dev/null; then
  echo "release qualification still runs MSRV inside the artifact job" >&2
  exit 1
fi

echo "release-qualification-exact-ci.test.sh: exact-head CI prerequisite is fail-closed"
