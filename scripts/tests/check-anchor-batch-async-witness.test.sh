#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

NORMAL_OUT="${TMP_DIR}/normal.out"
ADVISORY_OUT="${TMP_DIR}/advisory.out"
HELP_OUT="${TMP_DIR}/help.out"

bash "${REPO_ROOT}/scripts/check-anchor-batch-async-witness.sh" >"${NORMAL_OUT}"
grep -Fq "does NOT prove" "${NORMAL_OUT}"
grep -Fq "NOT proof or release evidence" "${NORMAL_OUT}"
grep -Fq "typed runtime gate and negative conformance tests" "${NORMAL_OUT}"

bash "${REPO_ROOT}/scripts/check-anchor-batch-async-witness.sh" --advisory >"${ADVISORY_OUT}"
grep -Fq "NOT proof or release evidence" "${ADVISORY_OUT}"
grep -Fq "typed runtime gate and negative conformance tests" "${ADVISORY_OUT}"

bash "${REPO_ROOT}/scripts/check-anchor-batch-async-witness.sh" --help >"${HELP_OUT}"
grep -Fq "not a sound proof" "${HELP_OUT}"
grep -Fq "release evidence" "${HELP_OUT}"

echo "PASS: anchor-batch async-witness lint remains explicitly non-evidentiary"
