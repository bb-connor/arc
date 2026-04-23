#!/usr/bin/env bash
set -euo pipefail

package_root="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${CHIO_GUARD_CPP_BUILD_DIR:-${package_root}/build}"

if [[ -z "${WASI_SDK_PATH:-}" ]]; then
  echo "set WASI_SDK_PATH to build C++ guard components" >&2
  exit 1
fi

cmake -S "${package_root}" -B "${build_dir}" \
  -DCHIO_GUARD_CPP_GENERATE=ON \
  -DCMAKE_TOOLCHAIN_FILE="${WASI_SDK_PATH}/share/cmake/wasi-sdk.cmake"
cmake --build "${build_dir}"
