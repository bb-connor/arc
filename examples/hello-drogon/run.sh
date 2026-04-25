#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${HELLO_DROGON_BUILD_DIR:-${EXAMPLE_ROOT}/.artifacts/build}"
CONFIGURE_LOG="${BUILD_DIR}/configure.log"
BUILD_LOG="${BUILD_DIR}/build.log"

if ! command -v cmake >/dev/null 2>&1; then
  echo "hello-drogon skipped: cmake was not found on PATH"
  exit 0
fi

mkdir -p "${BUILD_DIR}"

if ! cmake -S "${EXAMPLE_ROOT}" -B "${BUILD_DIR}" >"${CONFIGURE_LOG}" 2>&1; then
  echo "hello-drogon configure failed; see ${CONFIGURE_LOG}" >&2
  exit 1
fi

if [[ -f "${BUILD_DIR}/hello-drogon.skip" ]]; then
  echo "hello-drogon skipped: $(tr -d '\n' < "${BUILD_DIR}/hello-drogon.skip")"
  exit 0
fi

if ! cmake --build "${BUILD_DIR}" --target hello_drogon >"${BUILD_LOG}" 2>&1; then
  echo "hello-drogon build failed; see ${BUILD_LOG}" >&2
  exit 1
fi

exec "${BUILD_DIR}/hello_drogon"
