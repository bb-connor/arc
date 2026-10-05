#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-proof-room-docker-workspace.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

copy_path() {
  local path="$1"
  mkdir -p "${tmp_dir}/$(dirname "${path}")"
  cp -R "${repo_root}/${path}" "${tmp_dir}/${path}"
}

cp "${script_dir}/Cargo.toml" "${tmp_dir}/Cargo.toml"
cp "${script_dir}/Cargo.lock" "${tmp_dir}/Cargo.lock"

# Mirror the complete source closure consumed by the Proof Room Docker stage.
copy_path "crates"
copy_path "third_party"
copy_path "fixtures/proof-room/catalog.json"
copy_path "fixtures/proof-room/first-run/single-call-authority"
copy_path "spec/schemas/chio-proof-room"
copy_path "spec/schemas/chio-runtime"
copy_path "spec/schemas/chio-transaction"

(
  cd "${tmp_dir}"
  cargo metadata --format-version 1 --locked >/dev/null
  cargo check --locked -p chio-proof-room --bin chio-proof-room
)
