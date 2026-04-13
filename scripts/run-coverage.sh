#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo_root}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "coverage generation requires python3 on PATH" >&2
  exit 1
fi

coverage_root="${COVERAGE_ROOT:-${repo_root}/coverage}"
coverage_html_root="${coverage_root}/html"
coverage_log="${coverage_root}/tarpaulin.log"
coverage_json="${coverage_root}/tarpaulin-report.json"
coverage_lcov="${coverage_root}/lcov.info"
coverage_summary="${coverage_root}/summary.txt"
coverage_target_dir="${TARPAULIN_TARGET_DIR:-target/tarpaulin}"
coverage_timeout="${TARPAULIN_TIMEOUT_SECONDS:-600}"
coverage_engine="${TARPAULIN_ENGINE:-llvm}"
coverage_fail_under="${COVERAGE_FAIL_UNDER:-}"
tarpaulin_docker_image="${TARPAULIN_DOCKER_IMAGE:-xd009642/tarpaulin}"

mkdir -p "${coverage_root}" "${coverage_html_root}" "${coverage_target_dir}"
find "${coverage_root}" -mindepth 1 ! -name README.md -exec rm -rf {} +
mkdir -p "${coverage_html_root}"

tarpaulin_args=(
  --workspace
  --engine "${coverage_engine}"
  --timeout "${coverage_timeout}"
  --target-dir "${coverage_target_dir}"
  --out Html
  --out Json
  --out Lcov
  --exclude arc-formal-diff-tests
  --exclude arc-e2e
  --exclude hello-tool
  --exclude arc-conformance
  --exclude arc-control-plane
  --exclude arc-web3-bindings
)

if [[ "${TARPAULIN_SKIP_CLEAN:-false}" == "true" ]]; then
  tarpaulin_args+=(--skip-clean)
fi

if [[ -n "${coverage_fail_under}" ]]; then
  tarpaulin_args+=(--fail-under "${coverage_fail_under}")
fi

run_local_tarpaulin() {
  cargo tarpaulin "${tarpaulin_args[@]}"
}

run_docker_tarpaulin() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "coverage generation requires either cargo-tarpaulin or docker" >&2
    exit 1
  fi

  if [[ -n "${TARPAULIN_DOCKER_PLATFORM:-}" ]]; then
    docker run \
      --rm \
      --security-opt seccomp=unconfined \
      --user "$(id -u):$(id -g)" \
      --platform "${TARPAULIN_DOCKER_PLATFORM}" \
      --volume "${repo_root}:/volume" \
      --workdir /volume \
      "${tarpaulin_docker_image}" \
      cargo tarpaulin \
      "${tarpaulin_args[@]}"
  else
    docker run \
      --rm \
      --security-opt seccomp=unconfined \
      --user "$(id -u):$(id -g)" \
      --volume "${repo_root}:/volume" \
      --workdir /volume \
      "${tarpaulin_docker_image}" \
      cargo tarpaulin \
      "${tarpaulin_args[@]}"
  fi
}

if cargo tarpaulin --version >/dev/null 2>&1; then
  echo "running coverage with local cargo-tarpaulin"
  run_local_tarpaulin | tee "${coverage_log}"
else
  echo "running coverage with docker image ${tarpaulin_docker_image}"
  run_docker_tarpaulin | tee "${coverage_log}"
fi

if [[ ! -f "${repo_root}/tarpaulin-report.html" ]]; then
  echo "expected tarpaulin-report.html to be generated in ${repo_root}" >&2
  exit 1
fi
if [[ ! -f "${repo_root}/tarpaulin-report.json" ]]; then
  echo "expected tarpaulin-report.json to be generated in ${repo_root}" >&2
  exit 1
fi
if [[ ! -f "${repo_root}/lcov.info" ]]; then
  echo "expected lcov.info to be generated in ${repo_root}" >&2
  exit 1
fi

mv "${repo_root}/tarpaulin-report.html" "${coverage_html_root}/index.html"
mv "${repo_root}/tarpaulin-report.json" "${coverage_json}"
mv "${repo_root}/lcov.info" "${coverage_lcov}"

measured_coverage="$(
  python3 - "${coverage_log}" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text()
matches = re.findall(r'([0-9]+(?:\.[0-9]+)?)% coverage', text)
if not matches:
    raise SystemExit("failed to find measured coverage in tarpaulin output")
print(matches[-1])
PY
)"

{
  echo "Measured coverage: ${measured_coverage}%"
  if [[ -n "${coverage_fail_under}" ]]; then
    echo "Configured floor: ${coverage_fail_under}%"
  else
    echo "Configured floor: not enforced"
  fi
  echo "HTML report: coverage/html/index.html"
  echo "LCOV report: coverage/lcov.info"
  echo "JSON report: coverage/tarpaulin-report.json"
  echo "Tarpaulin log: coverage/tarpaulin.log"
} > "${coverage_summary}"

echo "coverage artifacts written to ${coverage_root}"
cat "${coverage_summary}"
