#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../../.." && pwd)"
build_dir="${CHIO_CPP_KERNEL_FFI_BUILD_DIR:-${repo_root}/target/chio-cpp-kernel-ffi}"
cargo_target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"

cd "${repo_root}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "chio-cpp-kernel FFI check requires cargo on PATH" >&2
  exit 1
fi
if ! command -v cmake >/dev/null 2>&1; then
  echo "chio-cpp-kernel FFI check requires cmake on PATH" >&2
  exit 1
fi

cargo test -p chio-cpp-kernel-ffi
cargo build -p chio-cpp-kernel-ffi

case "$(uname -s)" in
  Darwin)
    ffi_lib="${cargo_target_dir}/debug/libchio_cpp_kernel_ffi.a"
    ;;
  Linux)
    ffi_lib="${cargo_target_dir}/debug/libchio_cpp_kernel_ffi.a"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    ffi_lib="${cargo_target_dir}/debug/chio_cpp_kernel_ffi.lib"
    ;;
  *)
    ffi_lib="${cargo_target_dir}/debug/libchio_cpp_kernel_ffi.a"
    ;;
esac

if [[ ! -e "${ffi_lib}" ]]; then
  echo "expected kernel FFI library at ${ffi_lib}" >&2
  exit 1
fi

cmake -S sdks/cpp/chio-cpp-kernel -B "${build_dir}" \
  -DCHIO_CPP_KERNEL_BUILD_TESTS=ON \
  -DCHIO_CPP_KERNEL_BUILD_EXAMPLES=ON \
  -DCHIO_CPP_KERNEL_ENABLE_FFI=ON \
  -DCHIO_CPP_KERNEL_FFI_INCLUDE_DIR="${repo_root}/crates/sdk/chio-cpp-kernel-ffi/include" \
  -DCHIO_CPP_KERNEL_FFI_LIBRARY="${ffi_lib}"
cmake --build "${build_dir}"
ctest --test-dir "${build_dir}" --output-on-failure --no-tests=error

echo "chio-cpp-kernel FFI checks passed"
