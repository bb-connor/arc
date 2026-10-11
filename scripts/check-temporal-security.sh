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
  8 b94071e2e74ac084f799930bf67047f61452177f13e4b0633b563b2a7e4c0e8d \
  cargo test -p chio-quarantine --lib correlation::mutation_tests::

run_complete_inventory \
  "signed security event verification" \
  5 0e475ffcc30b39e6a044fe15e54f5940d3975d3ec64beee5d9ec16b7f9f7aaa0 \
  cargo test -p chio-core-types --test signed_security_event

run_filtered_inventory \
  "verified event provenance acceptance" \
  1 3e5a22878a3984c23efa565c39401ade413f34d9f35d6742568c5342b33e07d2 \
  cargo test -p chio-control-plane --lib \
  security::event_consumer::tests::verifier_accepts

run_filtered_inventory \
  "receipt-backed event provenance rejection" \
  2 a25a37d34b9ea683b638663a72744c7efd0882d3a10cd778e5a23471f52fb692 \
  cargo test -p chio-control-plane --lib \
  security::event_consumer::tests::receipt_provenance

run_filtered_inventory \
  "corrupt event ingress rejection" \
  2 42eb4e862632e64040b8cdcaaa91545a498a9a3d13ac4437cb28238e439659f1 \
  cargo test -p chio-control-plane --lib \
  security::event_consumer::tests::corrupt

run_filtered_inventory \
  "untrusted event producer rejection" \
  1 ea2b6112ddb1c8e4fef055629ab54023e1d2e082f445ce4080c33bffeed57d2f \
  cargo test -p chio-control-plane --lib \
  security::event_consumer::tests::otherwise_valid_event

run_filtered_inventory \
  "unconfigured event policy rejection" \
  7 de93fd69aae67a8f836966d826b6682ef20ff6986b83d3b6507edb74aa298d02 \
  cargo test -p chio-control-plane --lib \
  security::event_consumer::tests::trusted_producer_signature

run_filtered_inventory \
  "verified event ingress mutation matrix" \
  7 e7ab22f7b585933fc20bb4adb48775549bc0c72f7f6bfff94699c8f6daa2c56d \
  cargo test -p chio-control-plane --lib \
  security::event_consumer::tests::temporal_ingress::verifier_ingress_rejects_

if [[ "${completed_inventories}" -ne 10 ]] || [[ "${completed_tests}" -ne 51 ]]; then
  builtin printf '%s\n' \
    "Temporal security gate incomplete (${completed_inventories} inventories, ${completed_tests} tests)" >&2
  builtin exit 1
fi

builtin printf '%s\n' "Temporal security gate passed (10 committed inventories, 51 tests)"
