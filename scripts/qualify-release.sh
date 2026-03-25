#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v node >/dev/null 2>&1; then
  echo "release qualification requires node on PATH" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "release qualification requires python3 on PATH" >&2
  exit 1
fi

./scripts/ci-workspace.sh
./scripts/check-pact-py-release.sh
./scripts/check-pact-go-release.sh

output_root="target/release-qualification"
conformance_root="${output_root}/conformance"
log_root="${output_root}/logs"
rm -rf "${conformance_root}" "${log_root}"
mkdir -p "${conformance_root}" "${log_root}"

run_wave() {
  local wave="$1"
  shift
  local wave_dir="${conformance_root}/${wave}"
  mkdir -p "${wave_dir}/results"
cargo run -p pact-conformance --bin pact-conformance-runner -- \
    "$@" \
    --results-dir "${wave_dir}/results" \
    --report-output "${wave_dir}/report.md"
}

run_wave wave1
run_wave wave2 --scenarios-dir tests/conformance/scenarios/wave2
run_wave wave3 --auth-mode oauth-local --scenarios-dir tests/conformance/scenarios/wave3
run_wave wave4 --scenarios-dir tests/conformance/scenarios/wave4
run_wave wave5 --scenarios-dir tests/conformance/scenarios/wave5

cargo test -p pact-cli --test trust_cluster trust_control_cluster_repeat_run_qualification -- --ignored --nocapture \
  | tee "${log_root}/trust-cluster-repeat-run.log"
