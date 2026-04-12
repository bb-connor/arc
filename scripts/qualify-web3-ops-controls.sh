#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
  echo "web3 ops qualification requires jq on PATH" >&2
  exit 1
fi

output_root="target/web3-ops-qualification"
output_root_abs="$(pwd)/${output_root}"
log_path="${output_root}/qualification.log"
rm -rf "${output_root}"
mkdir -p "${output_root}"
: >"${log_path}"

run() {
  printf '==> %s\n' "$*" | tee -a "${log_path}"
  "$@" 2>&1 | tee -a "${log_path}"
}

run env ARC_WEB3_OPS_OUTPUT_DIR="${output_root_abs}" \
  CARGO_TARGET_DIR=target/arc-web3-ops-qualification \
  CARGO_INCREMENTAL=0 \
  CARGO_BUILD_JOBS=1 \
  cargo test -p arc-control-plane --test web3_ops_qualification -- --nocapture --test-threads=1

run jq empty \
  "${output_root}/runtime-reports/arc-link-runtime-report.json" \
  "${output_root}/runtime-reports/arc-anchor-runtime-report.json" \
  "${output_root}/runtime-reports/arc-settle-runtime-report.json" \
  "${output_root}/control-state/arc-link-control-state.json" \
  "${output_root}/control-state/arc-anchor-control-state.json" \
  "${output_root}/control-state/arc-settle-control-state.json" \
  "${output_root}/control-traces/arc-link-control-trace.json" \
  "${output_root}/control-traces/arc-anchor-control-trace.json" \
  "${output_root}/control-traces/arc-settle-control-trace.json" \
  "${output_root}/incident-audit.json"

printf 'web3 ops qualification complete; log written to %s\n' "${log_path}" | tee -a "${log_path}"
