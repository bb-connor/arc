#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

bash -n scripts/check-chio-drogon.sh scripts/setup-drogon-test-deps.sh
grep -Fq -- '-DCHIO_DROGON_REQUIRE_DEPS=ON' scripts/check-chio-drogon.sh
grep -Fq 'CHIO_DROGON_REQUIRE_DEPS=1 ./examples/hello-drogon/smoke.sh' scripts/check-chio-drogon.sh
grep -Fq 'cargo build --locked -p chio-cli --bin chio' scripts/check-chio-drogon.sh
grep -Fq 'CARGO_TARGET_DIR' scripts/check-chio-drogon.sh
grep -Fq -- '--no-tests=error' examples/hello-drogon/smoke.sh
test "$(grep -c -- '--no-tests=error' scripts/check-chio-drogon.sh)" -eq 2
if grep -Eq -- 'target help|package build skipped' scripts/check-chio-drogon.sh; then
  echo 'Drogon acceptance must not skip its configured package' >&2
  exit 1
fi
grep -Fq 'self.requires("drogon/1.9.12"' sdks/cpp/chio-drogon/conanfile.py
grep -Fq '89aca8c7993c8194f2c109c1d06a3b45bf363d5d' scripts/setup-drogon-test-deps.sh
grep -Fq 'test "$(git -C "${destination}" rev-parse HEAD)" = "${revision}"' scripts/setup-drogon-test-deps.sh
for gate in scripts/check-chio-cpp.sh sdks/cpp/chio-cpp-kernel/scripts/check-with-ffi.sh; do
  grep -Fq -- '--no-tests=error' "${gate}"
  grep -Fq 'CARGO_TARGET_DIR' "${gate}"
done
for workflow in .github/workflows/chio-cpp.yml .github/workflows/release-cpp.yml .github/workflows/sdk-parity.yml; do
  grep -Fq 'CMAKE_PREFIX_PATH="$(./scripts/setup-drogon-test-deps.sh)"' "${workflow}"
done
echo 'C++ consumer gates require real dependency and nonempty test execution'
