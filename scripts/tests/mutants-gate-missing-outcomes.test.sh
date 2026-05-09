#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

RELEASES_TOML="${TMP_DIR}/releases.toml"
cat >"${RELEASES_TOML}" <<'TOML'
[mutants]
target_catch_ratio_percent = 80
activation_threshold_percent_per_crate = 65
required_consecutive_nightly_successes = 2
observed_consecutive_nightly_successes = 2
cycle_end_tag = "v-test-blocking"
TOML

status=0
env \
  CHIO_RELEASES_TOML="${RELEASES_TOML}" \
  MUTANTS_PACKAGE=chio-kernel-core \
  MUTANTS_OUTPUT_DIR="${TMP_DIR}/mutants-out" \
  MUTANTS_EXIT=0 \
  bash "${REPO_ROOT}/scripts/mutants-gate.sh" \
  >"${TMP_DIR}/stdout" 2>"${TMP_DIR}/stderr" || status=$?

if [[ "${status}" -eq 0 ]]; then
  echo "FAIL: blocking mutation gate passed with missing outcomes.json" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

if ! grep -q "outcomes_json=missing" "${TMP_DIR}/stderr"; then
  echo "FAIL: missing outcomes.json failure did not explain the fail-closed reason" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

status=0
env \
  CHIO_RELEASES_TOML="${RELEASES_TOML}" \
  MUTANTS_PACKAGE=chio-kernel-core \
  MUTANTS_OUTPUT_DIR="${TMP_DIR}/mutants-out" \
  MUTANTS_EXIT=0 \
  MUTANTS_NO_DIFF=1 \
  bash "${REPO_ROOT}/scripts/mutants-gate.sh" \
  >"${TMP_DIR}/stdout" 2>"${TMP_DIR}/stderr" || status=$?

if [[ "${status}" -ne 0 ]]; then
  echo "FAIL: explicit no-diff mode should pass missing outcomes.json in blocking posture" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

if ! grep -q "verdict=pass-no-diff" "${TMP_DIR}/stdout"; then
  echo "FAIL: explicit no-diff success did not report pass-no-diff" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

mkdir -p "${TMP_DIR}/mutants-out"
python3 - "${TMP_DIR}/mutants-out/outcomes.json" <<'PY'
import json
import sys

outcomes = [{"summary": "CaughtMutant"} for _ in range(10)]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump({"outcomes": outcomes}, handle)
    handle.write("\n")
PY

status=0
env \
  CHIO_RELEASES_TOML="${RELEASES_TOML}" \
  MUTANTS_PACKAGE=chio-kernel-core \
  MUTANTS_OUTPUT_DIR="${TMP_DIR}/mutants-out" \
  MUTANTS_EXIT=124 \
  bash "${REPO_ROOT}/scripts/mutants-gate.sh" \
  >"${TMP_DIR}/stdout" 2>"${TMP_DIR}/stderr" || status=$?

if [[ "${status}" -eq 0 ]]; then
  echo "FAIL: blocking mutation gate passed interrupted run despite 100% caught outcomes" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

if ! grep -q "cargo-mutants exit was nonzero" "${TMP_DIR}/stderr"; then
  echo "FAIL: interrupted high-kill run did not report nonzero cargo-mutants exit" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

python3 - "${TMP_DIR}/mutants-out/outcomes.json" <<'PY'
import json
import sys

outcomes = [{"summary": "CaughtMutant"} for _ in range(13)]
outcomes.extend({"summary": "Missed"} for _ in range(7))
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump({"outcomes": outcomes}, handle)
    handle.write("\n")
PY

status=0
env \
  CHIO_RELEASES_TOML="${RELEASES_TOML}" \
  MUTANTS_PACKAGE=chio-kernel-core \
  MUTANTS_OUTPUT_DIR="${TMP_DIR}/mutants-out" \
  MUTANTS_EXIT=0 \
  bash "${REPO_ROOT}/scripts/mutants-gate.sh" \
  >"${TMP_DIR}/stdout" 2>"${TMP_DIR}/stderr" || status=$?

if [[ "${status}" -eq 0 ]]; then
  echo "FAIL: blocking mutation gate passed a 65% run below the 80% target" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

if ! grep -q "caught_ratio=65.0%" "${TMP_DIR}/stderr"; then
  echo "FAIL: below-target run did not report the 65% caught ratio" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

: >"${TMP_DIR}/override.log"
status=0
env \
  CHIO_RELEASES_TOML="${RELEASES_TOML}" \
  MUTANTS_PACKAGE=chio-kernel-core \
  MUTANTS_OUTPUT_DIR="${TMP_DIR}/mutants-out" \
  MUTANTS_EXIT=0 \
  MUTANTS_GATE_OVERRIDE_REASON="test override must not close release" \
  MUTANTS_OVERRIDE_AUDIT_LOG="${TMP_DIR}/override.log" \
  bash "${REPO_ROOT}/scripts/mutants-gate.sh" \
  >"${TMP_DIR}/stdout" 2>"${TMP_DIR}/stderr" || status=$?

if [[ "${status}" -eq 0 ]]; then
  echo "FAIL: MUTANTS_GATE_OVERRIDE_REASON produced closure/pass evidence" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

if ! grep -q "verdict=override-nonclosure" "${TMP_DIR}/stdout"; then
  echo "FAIL: override did not emit a non-closure verdict" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

if ! grep -q "test override must not close release" "${TMP_DIR}/override.log"; then
  echo "FAIL: override audit log was not written" >&2
  cat "${TMP_DIR}/override.log" >&2
  exit 1
fi

cat >"${TMP_DIR}/mutants-out/outcomes.json" <<'JSON'
{"outcomes":[{"summary":"CaughtMutant"}]}
JSON

status=0
env \
  CHIO_RELEASES_TOML="${RELEASES_TOML}" \
  MUTANTS_PACKAGE=chio-kernel-core \
  MUTANTS_OUTPUT_DIR="${TMP_DIR}/mutants-out" \
  MUTANTS_EXIT=0 \
  bash "${REPO_ROOT}/scripts/mutants-gate.sh" \
  >"${TMP_DIR}/stdout" 2>"${TMP_DIR}/stderr" || status=$?

if [[ "${status}" -eq 0 ]]; then
  echo "FAIL: blocking mutation gate passed a one-mutant subset" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

if ! grep -q "scoreable=1" "${TMP_DIR}/stderr"; then
  echo "FAIL: one-mutant subset failure did not report scoreable=1" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

status=0
env \
  CHIO_RELEASES_TOML="${RELEASES_TOML}" \
  MUTANTS_PACKAGE=chio-kernel-core \
  MUTANTS_OUTPUT_DIR="${TMP_DIR}/mutants-out" \
  MUTANTS_EXIT=0 \
  MUTANTS_MIN_SCOREABLE=1 \
  bash "${REPO_ROOT}/scripts/mutants-gate.sh" \
  >"${TMP_DIR}/stdout" 2>"${TMP_DIR}/stderr" || status=$?

if [[ "${status}" -eq 0 ]]; then
  echo "FAIL: blocking mutation gate accepted MUTANTS_MIN_SCOREABLE=1" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

if ! grep -q "blocking posture requires >= 2" "${TMP_DIR}/stderr"; then
  echo "FAIL: low min-scoreable override did not report the blocking lower bound" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

cat >"${TMP_DIR}/mutants-out/outcomes.json" <<'JSON'
{"outcomes":[]}
JSON

status=0
env \
  CHIO_RELEASES_TOML="${RELEASES_TOML}" \
  MUTANTS_PACKAGE=chio-kernel-core \
  MUTANTS_OUTPUT_DIR="${TMP_DIR}/mutants-out" \
  MUTANTS_EXIT=0 \
  bash "${REPO_ROOT}/scripts/mutants-gate.sh" \
  >"${TMP_DIR}/stdout" 2>"${TMP_DIR}/stderr" || status=$?

if [[ "${status}" -eq 0 ]]; then
  echo "FAIL: blocking mutation gate passed with empty outcomes.json" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

if ! grep -q "scoreable=0" "${TMP_DIR}/stderr"; then
  echo "FAIL: empty outcomes failure did not report scoreable=0" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

echo "PASS: blocking mutation gate fails closed on missing, empty, tiny, below-target, and override-nonclosure outcomes"
