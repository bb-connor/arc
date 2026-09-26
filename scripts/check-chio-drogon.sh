#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${CHIO_DROGON_BUILD_DIR:-${repo_root}/target/chio-drogon}"
example_build_dir="${CHIO_DROGON_EXAMPLE_BUILD_DIR:-${repo_root}/target/hello-drogon}"

cd "${repo_root}"

if ! command -v cmake >/dev/null 2>&1; then
  echo "chio-drogon checks require cmake on PATH" >&2
  exit 1
fi

cmake -S sdks/cpp/chio-drogon -B "${build_dir}" \
  -DCHIO_DROGON_BUILD_TESTS=ON \
  -DCHIO_DROGON_REQUIRE_DEPS=ON

# This is an acceptance gate, not the optional-dependency example launcher.
# Requiring configuration avoids treating missing dependencies or SIGPIPE in a
# target-help probe as successful qualification without compiling the library.
cmake --build "${build_dir}"
ctest --test-dir "${build_dir}" --output-on-failure --no-tests=error

cmake -S examples/hello-drogon -B "${example_build_dir}"
if [[ -f "${example_build_dir}/hello-drogon.skip" ]]; then
  echo "hello-drogon example dependencies are required for qualification" >&2
  exit 1
else
  cmake --build "${example_build_dir}" --target hello_drogon
  cmake --build "${example_build_dir}" --target hello_drogon_contract_tests
  ctest --test-dir "${example_build_dir}" --output-on-failure --no-tests=error
fi

bash -n examples/hello-drogon/run.sh examples/hello-drogon/smoke.sh
cargo build --locked -p chio-cli --bin chio
CHIO_BIN="${CARGO_TARGET_DIR:-${repo_root}/target}/debug/chio" \
  CHIO_DROGON_REQUIRE_DEPS=1 ./examples/hello-drogon/smoke.sh

echo "chio-drogon checks passed"
