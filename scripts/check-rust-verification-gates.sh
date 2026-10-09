#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for config in \
  .kani/harnesses.toml \
  formal/rust-verification/creusot-contracts.toml \
  formal/rust-verification/kani-harnesses.toml \
  formal/rust-verification/kani-public-harnesses.toml
do
  if [[ ! -f "${config}" ]]; then
    echo "Rust verification config missing: ${config}" >&2
    exit 1
  fi
done

# Validates every gate configuration and prints one notice per open proof
# residual; the notices are repeated after the executed checks.
open_residual_notices="$(python3 - <<'PY'
import re
import sys
from pathlib import Path

sys.path.insert(0, "scripts")
from kani_open_residual import FOLLOWUP, validate_open_residuals

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

loaded = {}
for rel, schema in expected.items():
    data = tomllib.loads(Path(rel).read_text(encoding="utf-8"))
    loaded[rel] = data
    if data.get("schema") != schema:
        raise SystemExit(f"schema mismatch in {rel}")
    if not data.get("covered_symbols") and not data.get("harness_groups"):
        raise SystemExit(f"missing coverage declaration in {rel}")

multi_rel = ".kani/harnesses.toml"
multi = tomllib.loads(Path(multi_rel).read_text(encoding="utf-8"))
if set(multi) != {"schema", "harness"}:
    raise SystemExit(
        f"{multi_rel} must contain only schema and harness tables"
    )
if multi.get("schema") != "chio.kani.multi-crate.v1":
    raise SystemExit(f"schema mismatch in {multi_rel}")
entries = multi.get("harness")
if not isinstance(entries, list) or not entries:
    raise SystemExit(f"{multi_rel} must contain a non-empty harness array")
try:
    open_residuals = validate_open_residuals(entries, require_expected=True)
except ValueError as error:
    raise SystemExit(str(error)) from error
required_keys = {"crate", "harness", "default_unwind", "timeout_secs", "lane"}
allowed_keys = required_keys | {
    "unwinding_checks",
    "require_cover",
    "open_residual",
    "memcmp_unwind",
    "public_key_eq_unwind",
    "public_key_hex_unwind",
    "p256_encoder_bounds",
    "features",
    "primary_rust_symbol",
    "notes",
}
seen_pairs = set()
for index, entry in enumerate(entries):
    label = f"{multi_rel} harness[{index}]"
    if not isinstance(entry, dict):
        raise SystemExit(f"{label} must be a table")
    missing = sorted(required_keys - set(entry))
    unknown = sorted(set(entry) - allowed_keys)
    if missing or unknown:
        raise SystemExit(f"{label} keys invalid: missing={missing} unknown={unknown}")
    crate = entry["crate"]
    harness = entry["harness"]
    if not isinstance(crate, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", crate):
        raise SystemExit(f"{label}.crate must be a normalized Cargo package name")
    if not isinstance(harness, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", harness):
        raise SystemExit(f"{label}.harness must be a Rust identifier")
    pair = (crate, harness)
    if pair in seen_pairs:
        raise SystemExit(f"{label} duplicates {crate}::{harness}")
    seen_pairs.add(pair)
    for field in ("default_unwind", "timeout_secs"):
        value = entry[field]
        if type(value) is not int or value < 1:
            raise SystemExit(f"{label}.{field} must be a positive integer")
    if entry["lane"] not in {"pr", "nightly"}:
        raise SystemExit(f"{label}.lane must be pr or nightly")
    if type(entry.get("unwinding_checks", False)) is not bool:
        raise SystemExit(f"{label}.unwinding_checks must be a boolean")
    require_cover = entry.get("require_cover", False)
    if type(require_cover) is not bool:
        raise SystemExit(f"{label}.require_cover must be a boolean")
    if require_cover and not entry.get("unwinding_checks", False):
        raise SystemExit(f"{label} cover requires unwinding checks")
    memcmp_unwind = entry.get("memcmp_unwind")
    if memcmp_unwind is not None:
        if type(memcmp_unwind) is not int or not 1 <= memcmp_unwind <= 2**32 - 1:
            raise SystemExit(f"{label}.memcmp_unwind must be a positive u32")
        if not require_cover:
            raise SystemExit(f"{label} memcmp override requires checked reachability")
    public_key_eq_unwind = entry.get("public_key_eq_unwind")
    if public_key_eq_unwind is not None:
        if type(public_key_eq_unwind) is not int or not 1 <= public_key_eq_unwind <= 2**32 - 1:
            raise SystemExit(f"{label}.public_key_eq_unwind must be a positive u32")
        if not require_cover or memcmp_unwind is not None:
            raise SystemExit(f"{label} key recursion override requires checked reachability and no memcmp override")
    public_key_hex_unwind = entry.get("public_key_hex_unwind")
    if public_key_hex_unwind is not None:
        if type(public_key_hex_unwind) is not int or not 0 <= public_key_hex_unwind <= 2**32 - 1:
            raise SystemExit(f"{label}.public_key_hex_unwind must be a u32")
        if not require_cover or memcmp_unwind is not None or public_key_eq_unwind is not None:
            raise SystemExit(f"{label} key hex override requires checked reachability and no other override")
    p256_encoder_bounds = entry.get("p256_encoder_bounds", False)
    if type(p256_encoder_bounds) is not bool:
        raise SystemExit(f"{label}.p256_encoder_bounds must be boolean")
    if p256_encoder_bounds and (
        public_key_hex_unwind is not None
        or public_key_eq_unwind is not None
        or memcmp_unwind is not None
        or not require_cover
        or not entry.get("unwinding_checks", False)
        or entry["crate"] != "chio-attest-verify"
        or entry["harness"] != "public_expect_report_data_determinism_and_binding"
        or entry["default_unwind"] != 136
    ):
        raise SystemExit(f"{label} standalone encoder profile requires checked reachability, the original P256 domain and no other override")
    features = entry.get("features", [])
    if not isinstance(features, list) or not all(
        isinstance(feature, str) and feature for feature in features
    ) or len(features) != len(set(features)):
        raise SystemExit(f"{label}.features must be a unique string list")
    primary = entry.get("primary_rust_symbol")
    if primary is not None and (not isinstance(primary, str) or not primary):
        raise SystemExit(f"{label}.primary_rust_symbol must be a non-empty string")
    notes = entry.get("notes")
    if notes is not None and not isinstance(notes, str):
        raise SystemExit(f"{label}.notes must be a string")

creusot_rel = "formal/rust-verification/creusot-contracts.toml"
creusot_prefix = "formal/rust-verification/creusot-core::"
contract_twins = loaded[creusot_rel].get("contract_twin")
if not isinstance(contract_twins, list) or not contract_twins:
    raise SystemExit("contract_twin must be a non-empty table array")
mapped_contracts = []
for index, twin in enumerate(contract_twins):
    if not isinstance(twin, dict) or not isinstance(twin.get("contract"), str):
        raise SystemExit(f"contract_twin[{index}] must declare a contract string")
    mapped_contracts.append(twin["contract"])
if len(mapped_contracts) != len(set(mapped_contracts)):
    raise SystemExit("duplicate Creusot contract entries in contract_twin")
contract_names = set(mapped_contracts)
covered_contracts = [
    symbol.removeprefix(creusot_prefix)
    for symbol in loaded[creusot_rel].get("covered_symbols", [])
    if symbol.startswith(creusot_prefix)
]
if len(covered_contracts) != len(set(covered_contracts)):
    raise SystemExit("duplicate Creusot contract entries in covered_symbols")
covered_names = set(covered_contracts)
missing_symbols = sorted(contract_names - covered_names)
stale_symbols = sorted(covered_names - contract_names)
if missing_symbols:
    raise SystemExit(
        "contract_twin entries missing from covered_symbols: " + ", ".join(missing_symbols)
    )
if stale_symbols:
    raise SystemExit(
        "covered_symbols entries missing from contract_twin: " + ", ".join(stale_symbols)
    )
for crate, harness in sorted(open_residuals):
    print(f"OPEN/UNPROVED: {crate}::{harness} ({FOLLOWUP}); not executed or counted as passed")
PY
)"
if [[ -z "${open_residual_notices}" ]]; then
  echo "Rust verification lost the open proof residual notice" >&2
  exit 1
fi

python3 scripts/check-kani-crypto-scope.py
./scripts/check-creusot-body-sync.sh

if [[ "${CHIO_RUST_VERIFICATION_METADATA_ONLY:-0}" == "1" ]]; then
  echo "Rust verification gate metadata passed; strict Creusot/Kani execution explicitly disabled"
  printf '%s\n' "${open_residual_notices}"
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
./scripts/run-kani-manifest.sh --lane pr --exclude-crate chio-kernel-core

# Last, so a truncated output tail still separates executed checks from each
# registered proof that is open and was not run.
echo "Strict Rust verification tools and executed registered Kani checks passed"
printf '%s\n' "${open_residual_notices}"
