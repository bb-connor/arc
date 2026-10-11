#!/usr/bin/env bash
# Preserve the proof command's failure and require its exact reachable witness.
set -euo pipefail
umask 077

if [[ $# -lt 2 ]]; then
  echo 'usage: run-kani-with-cover.sh <qualified-harness> [(--public-key-eq-unwind|--public-key-hex-unwind) <bound> | --p256-encoder-bounds] [--p256-encoder-bounds] -- <proof-command> [args...]' >&2
  exit 2
fi
harness="$1"
shift
public_key_unwind=""
public_key_function=""
p256_encoder_bounds=0
while [[ "${1:-}" == "--public-key-eq-unwind" || "${1:-}" == "--public-key-hex-unwind" || "${1:-}" == "--p256-encoder-bounds" ]]; do
  option="$1"
  bound="${2:-}"
  case "$option" in
    --p256-encoder-bounds)
      if [[ "$p256_encoder_bounds" -eq 1 ]]; then
        echo 'Select P256 encoder bounds at most once' >&2
        exit 2
      fi
      p256_encoder_bounds=1
      shift
      continue
      ;;
    --public-key-eq-unwind|--public-key-hex-unwind)
      if [[ ! "$bound" =~ ^(0|[1-9][0-9]{0,9})$ ]] || (( bound > 4294967295 )); then
        echo 'Proof profile bound must be an integer through 4294967295' >&2
        exit 2
      fi
      if [[ -n "$public_key_function" || ( "$option" == "--public-key-eq-unwind" && "$bound" == "0" ) ]]; then
        echo 'Select at most one PublicKey recursion profile; only hex allows zero' >&2
        exit 2
      fi
      public_key_unwind="$bound"
      if [[ "$option" == "--public-key-eq-unwind" ]]; then
        public_key_function="public-key-eq"
      else
        public_key_function="public-key-to-hex"
      fi
      ;;
  esac
  shift 2
done
if [[ "$p256_encoder_bounds" -eq 1 && "$public_key_function" == "public-key-eq" ]]; then
  echo 'P256 encoder bounds cannot use a PublicKey equality profile' >&2
  exit 2
fi
if [[ -n "$public_key_function" || "$p256_encoder_bounds" -eq 1 ]]; then
  if [[ "${1:-}" != "--" || $# -lt 2 ]]; then
    echo 'Proof profiles require -- followed by a proof command' >&2
    exit 2
  fi
  shift
  # This profile owns the CBMC delimiter and the output options. Refuse
  # composition that could hide the diagnostic or change the proof checks.
  for argument in "$@"; do
    case "$argument" in
      --cbmc-args|--cbmc-args=*|--default-unwind|--default-unwind=*|--unwind|--unwind=*|--unwindset|--unwindset=*|--no-*-checks|--no-*-checks=*|--no-unwinding-assertions|--no-unwinding-assertions=*|--output-format|--output-format=*|--export-json|--export-json=*|--public-key-eq-unwind|--public-key-eq-unwind=*|--public-key-hex-unwind|--public-key-hex-unwind=*|--p256-encoder-bounds|--p256-encoder-bounds=*|--)
        echo "Proof profile conflicts with argument: $argument" >&2
        exit 2
        ;;
    esac
  done
fi
result_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-kani-cover.XXXXXXXX")"
trap 'rm -rf -- "$result_dir"' EXIT

function_bound=""
if [[ -n "$public_key_function" ]]; then
  # The supported diagnostic lists the freshly prepared exact model without
  # symbolic execution. Old output mode bypasses Kani's result parser; its
  # successful exit and summary are only preparation, never proof evidence.
  "$@" --output-format old -Z unstable-options --cbmc-args --list-goto-functions > "$result_dir/functions.log"
  function_bound="$(python3 "$(dirname "$0")/check-kani-function-bound.py" "$result_dir/functions.log" "$public_key_unwind" --function "$public_key_function")"
fi
if [[ "$p256_encoder_bounds" -eq 1 ]]; then
  # Require every fixed encoder/SHA source role in the freshly prepared model.
  # This profile does not request an unrelated owned-renderer function bound.
  "$@" --output-format old -Z unstable-options --cbmc-args --show-loops > "$result_dir/loops.log"
  p256_bounds="$(python3 "$(dirname "$0")/check-kani-function-bound.py" "$result_dir/loops.log" --p256-encoder-bounds)"
  if [[ -n "$function_bound" ]]; then
    function_bound="${function_bound},${p256_bounds}"
  else
    function_bound="$p256_bounds"
  fi
fi
if [[ -n "$function_bound" ]]; then
  set -- "$@" --cbmc-args --unwindset "$function_bound"
fi
# Kani 0.68 reports uncovered cover properties without failing verification.
# Its machine-readable result lets the caller enforce this additional contract.
# Arguments after --cbmc-args belong to CBMC, so export options must precede
# that delimiter. Preserve every original argument and the command's status.
proof_command=()
export_added=0
for argument in "$@"; do
  if [[ "$argument" == "--cbmc-args" && "$export_added" -eq 0 ]]; then
    proof_command+=(-Z unstable-options --export-json "$result_dir/result.json")
    export_added=1
  fi
  proof_command+=("$argument")
done
if [[ "$export_added" -eq 0 ]]; then
  proof_command+=(-Z unstable-options --export-json "$result_dir/result.json")
fi
"${proof_command[@]}"
python3 "$(dirname "$0")/check-kani-cover.py" "$result_dir/result.json" "$harness"
