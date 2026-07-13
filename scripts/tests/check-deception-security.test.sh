#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/check-deception-security.sh"
test -x "${runner}"
bash -n "${runner}"

for required in \
  'cargo test -p chio-decoy --all-targets' \
  'cargo test -p chio-security-kernel --test adapters tripwire' \
  'cargo test -p chio-security-kernel --test adapters post_output_match' \
  'cargo test -p chio-store-sqlite --test sealed_decoy_registry' \
  'matched zero tests'
do
  grep -Fq "${required}" "${runner}"
done

echo "Deception security gate contract passed"
