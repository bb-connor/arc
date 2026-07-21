#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

lane="${1:---all}"
if [[ "$#" -gt 1 ]] || [[ ! "${lane}" =~ ^--(all|baseline|model|persistence)$ ]]; then
  echo "usage: $0 [--all|--baseline|--model|--persistence]" >&2
  exit 64
fi

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

run_committed_inventory() {
  local label="$1"
  local expected_count="$2"
  local expected_sha256="$3"
  shift 3
  ./scripts/run-exact-cargo-test-inventory.sh \
    --label "${label}" \
    --allow-filtered \
    --expected-count "${expected_count}" \
    --expected-sha256 "${expected_sha256}" -- \
    "$@"
}

run_complete_inventory() {
  local label="$1"
  local expected_count="$2"
  local expected_sha256="$3"
  shift 3
  ./scripts/run-exact-cargo-test-inventory.sh \
    --label "${label}" \
    --expected-count "${expected_count}" \
    --expected-sha256 "${expected_sha256}" -- \
    "$@"
}

run_baseline() {
  run_committed_inventory \
    "kernel budget characterization" \
    47 d303cf87af81c0345c0f7b027abc585beae02de147ce343ce462e2998e295144 \
    cargo test -p chio-kernel --lib kernel::tests::budget::
  run_committed_inventory \
    "kernel approval characterization" \
    9 48f3a5f8b13080ea6a618930e8880b3492d292e7eec6aa6121aa53f038cd5f9a \
    cargo test -p chio-kernel --lib kernel::tests::approval_flow::
  run_committed_inventory \
    "kernel governed budget-chain characterization" \
    18 ea85fd29d5a0457a9e8505edac9df98306ce9253093722f5b4584a22eaadd5d7 \
    cargo test -p chio-kernel --lib kernel::tests::budget_governed_call_chain::
  run_committed_inventory \
    "SQLite budget characterization" \
    148 50a700ff183acddad12aafc19454daba121175a97a1f2235da10cb43f4242277 \
    cargo test -p chio-store-sqlite --lib budget_store::tests::
}

run_model() {
  run_committed_inventory \
    "aggregate root model" \
    32 1a31ce3998ff5e55fa6dc29df3881bd96a63afc6b64456d245c8dce23035d3ad \
    cargo test -p chio-core-types --features fips --lib capability::aggregate_budget::tests::
  run_committed_inventory \
    "aggregate attenuation model" \
    21 c870588f3df03b00e330cbd54909b0d572b1b6098820716dc9e2a5f433e042f2 \
    cargo test -p chio-core-types --lib capability::aggregate_invocation_attenuation_tests::
  run_committed_inventory \
    "delegation family model" \
    22 0d5deced8bc0768f62323fda49b1918d8c3bd1cda0b0239de019b702611d256a \
    cargo test -p chio-core-types --lib capability::delegation_family_tests::
  run_committed_inventory \
    "portable capability verification" \
    17 2dcd4618aed0a0d6cd8640c3491e6f55e5b1ee07ef4a094081f1d262f04b7d49 \
    cargo test -p chio-kernel-core --lib capability_verify::tests::
  run_complete_inventory \
    "generated security binding corpus" \
    10 e639c883d1ef53aeb6e2f6b0999437b463384cb3c27689357ae50b1bb2439457 \
    cargo test -p chio-core-types --test security_generated_vectors
}

run_persistence() {
  run_committed_inventory \
    "SQLite composite budget persistence" \
    148 50a700ff183acddad12aafc19454daba121175a97a1f2235da10cb43f4242277 \
    cargo test -p chio-store-sqlite --lib budget_store::tests::
  run_committed_inventory \
    "control-plane budget composition" \
    30 9529b68ef730fa89fdcf97a765785065b4974a2094e9d504436f61abe0873fe1 \
    cargo test -p chio-control-plane --lib trust_control::service_runtime::tests::budget::
  run_committed_inventory \
    "control-plane admission consensus" \
    61 32fbb12defdf3e5d9f64e4a9524e5cde07f06d963cda7f168c6d2bb2e4a3476e \
    cargo test -p chio-control-plane --lib trust_control::cluster::admission_consensus::tests::
  run_complete_inventory \
    "protocol primitives tier 1 conformance" \
    10 d95926bf0e3365769b9dc427d3626b324d4d8faa5372099886863f569054abd0 \
    cargo test -p chio-conformance --test protocol_primitives_t1
  run_complete_inventory \
    "protocol primitives tier 2 conformance" \
    10 57e3a4d278a7a51b9fb48ee2ac86a2bf16ef791d60cc0a81e38d12f1eae42db5 \
    cargo test -p chio-conformance --test protocol_primitives_t2
}

python3 scripts/check-protocol-primitives-vectors.py

case "${lane}" in
  --all)
    run_baseline
    run_model
    run_persistence
    ;;
  --baseline)
    run_baseline
    ;;
  --model)
    run_model
    ;;
  --persistence)
    run_persistence
    ;;
esac

echo "Protocol-primitives focused gate passed (${lane#--})"
