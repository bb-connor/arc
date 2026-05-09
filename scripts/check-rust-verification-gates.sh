#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for config in \
  formal/rust-verification/creusot-contracts.toml \
  formal/rust-verification/kani-harnesses.toml \
  formal/rust-verification/kani-public-harnesses.toml
do
  if [[ ! -f "${config}" ]]; then
    echo "Rust verification config missing: ${config}" >&2
    exit 1
  fi
done

python3 - <<'PY'
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError as exc:
        raise SystemExit("tomllib or tomli is required for Rust verification gate checks") from exc

expected = {
    "formal/rust-verification/creusot-contracts.toml": "chio.creusot-contracts.v1",
    "formal/rust-verification/kani-harnesses.toml": "chio.kani-harnesses.v1",
    "formal/rust-verification/kani-public-harnesses.toml": "chio.kani-public-harnesses.v1",
}

for rel, schema in expected.items():
    data = tomllib.loads(Path(rel).read_text(encoding="utf-8"))
    if data.get("schema") != schema:
        raise SystemExit(f"schema mismatch in {rel}")
    if not data.get("covered_symbols") and not data.get("harness_groups"):
        raise SystemExit(f"missing coverage declaration in {rel}")
    if rel.endswith("kani-public-harnesses.toml"):
        if data.get("evidence_class") != "bounded_no_unwinding":
            raise SystemExit(f"{rel}: expected evidence_class=bounded_no_unwinding")
        if data.get("full_soundness_evidence") is not False:
            raise SystemExit(f"{rel}: expected full_soundness_evidence=false")
        if data.get("unwinding_assertions") is not False:
            raise SystemExit(f"{rel}: strict release wording requires explicit bounded/no-unwinding posture")
PY

if [[ "${CHIO_RUST_VERIFICATION_METADATA_ONLY:-0}" == "1" ]]; then
  echo "CHIO_RUST_VERIFICATION_METADATA_ONLY is deprecated and cannot satisfy release evidence; use CHIO_RUST_VERIFICATION_INVENTORY_LINT_ONLY=1 for non-release inventory lint" >&2
  exit 1
fi

if [[ "${CHIO_RUST_VERIFICATION_INVENTORY_LINT_ONLY:-0}" == "1" ]]; then
  echo "Rust verification inventory lint passed; strict Creusot/Kani execution was not run and this output is not release evidence"
  exit 0
fi

if ! command -v creusot >/dev/null 2>&1 && ! cargo creusot --help >/dev/null 2>&1; then
  echo "strict Rust verification requires Creusot on PATH or cargo-creusot installed" >&2
  exit 1
fi

if ! command -v kani >/dev/null 2>&1 && ! cargo kani --help >/dev/null 2>&1; then
  echo "strict Rust verification requires Kani on PATH or cargo-kani installed" >&2
  exit 1
fi

./scripts/check-creusot-smoke.sh
./scripts/check-kani-smoke.sh
./scripts/check-creusot-core.sh
./scripts/check-kani-core.sh
./scripts/check-kani-public-core.sh

echo "Strict Rust verification tools and core checks passed"
