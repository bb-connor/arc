#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

test_name="budget_store::property_tests::loom_production_composite_quota_authorization_is_all_or_none"

cargo test \
  -p chio-kernel \
  --lib \
  --features loom-tests \
  "${test_name}" \
  -- \
  --exact

echo "Protocol-primitives production Loom gate passed"
