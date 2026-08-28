#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
workflow="${repo_root}/.github/workflows/release-qualification.yml"
ci_workflow="${repo_root}/.github/workflows/ci.yml"
qualification="${repo_root}/scripts/qualify-release.sh"
waiter="${repo_root}/scripts/wait-for-exact-ci.sh"

for marker in \
  "Exact-head CI prerequisite" \
  "needs: exact_ci" \
  "run: ./scripts/wait-for-exact-ci.sh" \
  "CHIO_RELEASE_WORKSPACE_GATE_MODE: exact-ci" \
  'CHIO_EXACT_CI_RUN_ID: ${{ needs.exact_ci.outputs.run_id }}' \
  "Release MSRV full-workspace test" \
  "cargo test --workspace"; do
  grep -F "${marker}" "${workflow}" >/dev/null
done

grep -F 'workspace_gate_mode="${CHIO_RELEASE_WORKSPACE_GATE_MODE:-local}"' "${qualification}" >/dev/null
grep -F 'if [[ "${GITHUB_ACTIONS:-}" != "true" ]]' "${qualification}" >/dev/null
grep -F 'exact-ci-run-id.txt' "${qualification}" >/dev/null
grep -F 'actions/workflows/ci.yml/runs' "${waiter}" >/dev/null
grep -F 'select(.event == "push" or .event == "workflow_dispatch")' "${waiter}" >/dev/null
grep -F 'gh workflow run ci.yml' "${waiter}" >/dev/null
grep -F 'if [[ "${conclusion}" != "success" ]]' "${waiter}" >/dev/null
grep -F 'workflow_dispatch:' "${ci_workflow}" >/dev/null
grep -F 'bash scripts/tests/release-qualification-exact-ci.test.sh' "${ci_workflow}" >/dev/null
grep -F 'bash scripts/tests/check-creusot-contract-sync.test.sh' "${qualification}" >/dev/null
grep -F 'rm -f "${output_root}/exact-ci-run-id.txt"' "${qualification}" >/dev/null
grep -F 'rustup target add wasm32-unknown-unknown --toolchain 1.93.0' "${workflow}" >/dev/null
grep -F 'bun-version: "1.3.3"' "${workflow}" >/dev/null
[[ "$(grep -Fc 'pnpm --dir contracts install --frozen-lockfile' "${workflow}")" -eq 2 ]]
grep -F 'wait_seconds="${CHIO_EXACT_CI_WAIT_SECONDS:-21600}"' "${waiter}" >/dev/null
grep -F 'timeout-minutes: 360' "${workflow}" >/dev/null
grep -F 'timeout-minutes: 345' "${ci_workflow}" >/dev/null

if grep -F "cargo +1.93.0" "${workflow}" >/dev/null; then
  echo "release qualification still runs MSRV inside the artifact job" >&2
  exit 1
fi

echo "release-qualification-exact-ci.test.sh: exact-head CI prerequisite is fail-closed"
