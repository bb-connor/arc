#!/bin/bash -p
set -euo pipefail

if ! builtin shopt -qo privileged; then
  builtin printf '%s\n' "temporal security gate requires Bash privileged mode" >&2
  builtin exit 64
fi

script_source="${BASH_SOURCE[0]}"
if [[ "${script_source}" != /* ]]; then
  script_source="$(builtin pwd -P)/${script_source}"
fi
if [[ -L "${script_source}" ]]; then
  builtin printf '%s\n' "temporal security gate refuses a symlinked script path" >&2
  builtin exit 64
fi
script_dir="$(CDPATH= builtin cd -P -- "${script_source%/*}" && builtin pwd -P)"
repo_root="$(CDPATH= builtin cd -P -- "${script_dir}/.." && builtin pwd -P)"
builtin cd -- "${repo_root}"

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

completed_inventories=0
completed_tests=0

run_complete_inventory() {
  local label="$1"
  local expected_count="$2"
  local expected_sha256="$3"
  shift 3
  if /bin/bash -p ./scripts/run-exact-cargo-test-inventory.sh \
      --label "${label}" \
      --expected-count "${expected_count}" \
      --expected-sha256 "${expected_sha256}" -- \
      "$@"; then
    completed_inventories=$((completed_inventories + 1))
    completed_tests=$((completed_tests + expected_count))
  else
    return "$?"
  fi
}

run_filtered_inventory() {
  local label="$1"
  local expected_count="$2"
  local expected_sha256="$3"
  shift 3
  if /bin/bash -p ./scripts/run-exact-cargo-test-inventory.sh \
      --label "${label}" \
      --allow-filtered \
      --expected-count "${expected_count}" \
      --expected-sha256 "${expected_sha256}" -- \
      "$@"; then
    completed_inventories=$((completed_inventories + 1))
    completed_tests=$((completed_tests + expected_count))
  else
    return "$?"
  fi
}

run_complete_inventory \
  "temporal rule validation" \
  2 a44f2fb52b1e55f9b1e874bbb4f84b92a1e06477ed1478911fe39dcbdd5c2bcd \
  cargo test -p chio-quarantine --test rules

run_complete_inventory \
  "temporal event-time correlation" \
  16 755ee67c8cb26f7bec81c62c28b84c7f0c0e00ac139f20d95e2ce36aabd09ef4 \
  cargo test -p chio-quarantine --test correlation

run_filtered_inventory \
  "temporal correlation mutation controls" \
  3 45e153188daf9b432216830a967d6c5a1e7b51078e33f065f1a05b9144536563 \
  cargo test -p chio-quarantine --lib correlation::mutation_tests::

run_complete_inventory \
  "signed security event verification" \
  5 0e475ffcc30b39e6a044fe15e54f5940d3975d3ec64beee5d9ec16b7f9f7aaa0 \
  cargo test -p chio-core-types --test signed_security_event

run_filtered_inventory \
  "verified event provenance acceptance" \
  1 7806a32aafcb999dee16b3ba7fb2f9cd2e6630e1310a8500a85b322022259713 \
  cargo test -p chio-control-plane --lib \
  security::event_consumer::tests::verifier_accepts

run_filtered_inventory \
  "receipt-backed event provenance rejection" \
  2 7f58513090b4b1b09841047e9000f92ab0beaa5d786eaabfa91801ee7641710d \
  cargo test -p chio-control-plane --lib \
  security::event_consumer::tests::receipt_provenance

run_filtered_inventory \
  "corrupt event ingress rejection" \
  2 089f9974ccc2d7ac6ab0cf01e7272a549efa3930e73c388a3b4a4b9cc9745eb9 \
  cargo test -p chio-control-plane --lib \
  security::event_consumer::tests::corrupt

run_filtered_inventory \
  "untrusted event producer rejection" \
  1 a9e1c7c6377dda82a1747deb7f5bcf0b6190c205fb46accbe75f66f9c3f90e12 \
  cargo test -p chio-control-plane --lib \
  security::event_consumer::tests::otherwise_valid_event

run_filtered_inventory \
  "unconfigured event policy rejection" \
  1 b10498bfdde0e6bfae57ad7aa6fb284132c290171263c7c27849dba7ee03a074 \
  cargo test -p chio-control-plane --lib \
  security::event_consumer::tests::trusted_producer_signature

run_filtered_inventory \
  "verified event ingress mutation matrix" \
  7 7472d4b71e744bc7c191eda45e9e18ceff0a239bda9963244a16df7f60dc60bb \
  cargo test -p chio-control-plane --lib \
  security::event_consumer::tests::verifier_ingress_rejects_

if [[ "${completed_inventories}" -ne 10 ]] || [[ "${completed_tests}" -ne 40 ]]; then
  builtin printf '%s\n' \
    "Temporal security gate incomplete (${completed_inventories} inventories, ${completed_tests} tests)" >&2
  builtin exit 1
fi

builtin printf '%s\n' "Temporal security gate passed (10 committed inventories, 40 tests)"
