#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

pilot_source="formal/aeneas/verified_core.rs"
work_dir="target/formal/aeneas-pilot"
llbc_dir="${work_dir}/llbc"
lean_dir="${work_dir}/lean"

if [[ ! -f "${pilot_source}" ]]; then
  echo "Aeneas pilot source missing: ${pilot_source}" >&2
  exit 1
fi

if ! command -v aeneas >/dev/null 2>&1; then
  echo "Aeneas pilot check requires aeneas on PATH" >&2
  exit 1
fi

if [[ -n "${CHIO_CHARON:-}" ]]; then
  charon_bin="${CHIO_CHARON}"
elif [[ -x "${HOME}/.cargo/bin/charon" ]]; then
  charon_bin="${HOME}/.cargo/bin/charon"
elif command -v charon >/dev/null 2>&1; then
  charon_bin="$(command -v charon)"
else
  echo "Aeneas pilot check requires charon on PATH" >&2
  exit 1
fi

rm -rf "${work_dir}"
mkdir -p "${llbc_dir}" "${lean_dir}"

echo "==> Charon extraction for Aeneas pilot"
"${charon_bin}" rustc --preset=aeneas --dest "${llbc_dir}" -- \
  --crate-type lib "${pilot_source}"

llbc_file="${llbc_dir}/verified_core.llbc"
if [[ ! -f "${llbc_file}" ]]; then
  echo "Aeneas pilot check failed: Charon did not produce ${llbc_file}" >&2
  exit 1
fi

echo "==> Aeneas Lean extraction for pure verified-core pilot"
aeneas -backend lean -split-files -namespace Chio.AeneasPilot \
  -dest "${lean_dir}" "${llbc_file}"

funs_file="${lean_dir}/Funs.lean"
types_file="${lean_dir}/Types.lean"
if [[ ! -f "${funs_file}" || ! -f "${types_file}" ]]; then
  echo "Aeneas pilot check failed: expected Lean output files are missing" >&2
  exit 1
fi

for symbol in \
  time_window_valid \
  dpop_subset \
  budget_precheck \
  governed_approval_passes \
  evaluate_signature_time_scope \
  report_may_use_verified_label
do
  if ! grep -q "def ${symbol}" "${funs_file}"; then
    echo "Aeneas pilot check failed: generated Lean is missing ${symbol}" >&2
    exit 1
  fi
done

if ! grep -q "inductive Decision" "${types_file}"; then
  echo "Aeneas pilot check failed: generated Lean is missing Decision" >&2
  exit 1
fi

echo "Aeneas pilot check passed"
