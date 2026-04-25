#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
APP_ROOT="${EXAMPLE_ROOT}/app"

# The Chio Evidence Console Playwright e2e suite is opt-in. It runs
# automatically when either:
#   - the caller sets CHIO_RUN_E2E=1 (explicit opt-in), or
#   - the app has already been installed (node_modules present AND
#     @playwright/test already resolved).
# This keeps `smoke.sh` working on hosts without a JS toolchain while
# exercising the UI end-to-end on developer laptops and CI workers that
# have opted into the heavier path.

want_e2e=0
if [[ "${CHIO_RUN_E2E:-0}" == "1" ]]; then
  want_e2e=1
fi
if [[ "${CHIO_RUN_E2E:-}" != "0" && -d "${APP_ROOT}/node_modules/@playwright/test" ]]; then
  want_e2e=1
fi

# If we are going to run e2e, pin the artifact root up-front so we can
# hand it to the scenario via --artifact-dir. This keeps the path known
# before the scenario script prints it and avoids having to grep stdout.
scenario_args=("$@")
run_e2e=0
if [[ "${want_e2e}" == "1" ]]; then
  # Honour an explicit --artifact-dir if the caller provided one; otherwise
  # mint one under the example artifacts root.
  has_artifact_dir=0
  for arg in ${scenario_args[@]+"${scenario_args[@]}"}; do
    if [[ "${arg}" == "--artifact-dir" ]]; then
      has_artifact_dir=1
      break
    fi
  done

  # --help must short-circuit the e2e wrapper.
  for arg in ${scenario_args[@]+"${scenario_args[@]}"}; do
    if [[ "${arg}" == "--help" || "${arg}" == "-h" ]]; then
      has_artifact_dir=-1
      break
    fi
  done

  if [[ "${has_artifact_dir}" == "0" ]]; then
    artifact_dir="${EXAMPLE_ROOT}/artifacts/web3-service-order/$(date -u +%Y%m%dT%H%M%SZ)-e2e"
    scenario_args+=(--artifact-dir "${artifact_dir}")
    ARTIFACT_ROOT="${artifact_dir}"
    run_e2e=1
  elif [[ "${has_artifact_dir}" == "1" ]]; then
    # Extract the provided artifact-dir for the e2e step.
    for (( i=0; i<${#scenario_args[@]}; i++ )); do
      if [[ "${scenario_args[$i]}" == "--artifact-dir" ]]; then
        ARTIFACT_ROOT="${scenario_args[$((i+1))]}"
        break
      fi
    done
    run_e2e=1
  fi
fi

CHIO_E2E_NEXT_PID=""
cleanup_next_server() {
  if [[ -n "${CHIO_E2E_NEXT_PID}" ]] && kill -0 "${CHIO_E2E_NEXT_PID}" 2>/dev/null; then
    kill "${CHIO_E2E_NEXT_PID}" 2>/dev/null || true
    wait "${CHIO_E2E_NEXT_PID}" 2>/dev/null || true
  fi
}
trap cleanup_next_server EXIT

"${EXAMPLE_ROOT}/scenario/01-web3-service-order.sh" ${scenario_args[@]+"${scenario_args[@]}"}

if [[ "${run_e2e}" != "1" ]]; then
  exit 0
fi

if [[ -z "${ARTIFACT_ROOT:-}" || ! -d "${ARTIFACT_ROOT}" ]]; then
  echo "e2e: expected ARTIFACT_ROOT to exist after scenario, got '${ARTIFACT_ROOT:-}'" >&2
  exit 1
fi

# Source helpers for pick_free_port / wait_for_http.
# shellcheck source=/dev/null
source "${EXAMPLE_ROOT}/../_shared/hello-http-common.sh"

# Build the Next app if needed. `.next/BUILD_ID` is the cheapest
# staleness check; a missing or corrupted build triggers a rebuild.
if [[ ! -f "${APP_ROOT}/.next/BUILD_ID" ]]; then
  (cd "${APP_ROOT}" && bun run build >"${ARTIFACT_ROOT}/logs/next-build.log" 2>&1)
fi

CHIO_E2E_PORT="$(pick_free_port)"
mkdir -p "${ARTIFACT_ROOT}/logs"

(
  cd "${APP_ROOT}" \
    && CHIO_BUNDLE_DIR="${ARTIFACT_ROOT}" PORT="${CHIO_E2E_PORT}" \
       bun run start \
       >"${ARTIFACT_ROOT}/logs/next.log" 2>&1
) &
CHIO_E2E_NEXT_PID=$!

wait_for_http "http://127.0.0.1:${CHIO_E2E_PORT}/api/health"

(
  cd "${APP_ROOT}" \
    && CHIO_E2E_BASE_URL="http://127.0.0.1:${CHIO_E2E_PORT}" \
       bun run test:e2e --reporter=line --project=chromium
)

printf 'playwright e2e passed\n'
