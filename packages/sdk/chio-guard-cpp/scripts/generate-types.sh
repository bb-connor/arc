#!/usr/bin/env bash
set -euo pipefail

package_root="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "${package_root}/../../.." && pwd)"
out_dir="${CHIO_GUARD_CPP_GENERATED_DIR:-${package_root}/generated}"
wit_file="${CHIO_GUARD_CPP_WIT:-${repo_root}/wit/chio-guard/world.wit}"

if ! command -v wit-bindgen >/dev/null 2>&1; then
  echo "chio-guard-cpp generation requires wit-bindgen on PATH" >&2
  exit 1
fi

mkdir -p "${out_dir}"
wit-bindgen cpp --world guard --out-dir "${out_dir}" "${wit_file}"

echo "generated chio guard C++ bindings in ${out_dir}"
