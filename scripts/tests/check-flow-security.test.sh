#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/check-flow-security.sh"
test -x "${runner}"
bash -n "${runner}"

for required in \
  'formal/tla/MCInformationFlowLattice.cfg' \
  'MCInformationFlowLatticeReaderDirectionBroken.cfg' \
  'wasm32-unknown-unknown' \
  'cargo test -p chio-flow --all-targets' \
  'cargo test -p chio-manifest --test manifest_v2' \
  'cargo test -p chio-security-kernel --test adapters flow_' \
  'cargo test -p chio-store-sqlite --test security_state' \
  'cargo test -p chio-control-plane --test security_runtime' \
  'matched zero tests'
do
  grep -Fq "${required}" "${runner}"
done

echo "Flow security gate contract passed"
