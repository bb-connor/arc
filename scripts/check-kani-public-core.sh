#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! cargo kani --version >/dev/null 2>&1; then
  echo "Kani public core check requires cargo-kani" >&2
  exit 1
fi

python3 - <<'PY'
from pathlib import Path

source = Path("crates/chio-kernel-core/src/kani_public_harnesses.rs")
text = source.read_text(encoding="utf-8")
expected = [
    "public_verify_capability_rejects_untrusted_issuer_before_signature",
    "public_normalized_scope_subset_rejects_widened_child",
    "public_resolve_matching_grants_rejects_out_of_scope_request",
    "public_evaluate_rejects_untrusted_issuer_before_dispatch",
    "public_sign_receipt_rejects_kernel_key_mismatch_before_signing",
]
missing = [name for name in expected if f"fn {name}" not in text]
if missing:
    raise SystemExit(f"missing public Kani harnesses: {missing}")
PY

cargo kani -p chio-kernel-core --lib --default-unwind 8 --no-unwinding-checks

echo "Kani public core harnesses passed"
