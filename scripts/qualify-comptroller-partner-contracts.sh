#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1; then
  echo "comptroller partner-contract qualification requires cargo on PATH" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "comptroller partner-contract qualification requires python3 on PATH" >&2
  exit 1
fi

output_root="target/release-qualification/comptroller-partner-contracts"
log_root="${output_root}/logs"
manifest_path="${output_root}/artifact-manifest.json"
checksum_path="${output_root}/SHA256SUMS"
report_path="${output_root}/qualification-report.md"
matrix_src="docs/standards/CHIO_PARTNER_RECEIPT_SETTLEMENT_CONTRACT_MATRIX.json"
matrix_snapshot="${output_root}/CHIO_PARTNER_RECEIPT_SETTLEMENT_CONTRACT_MATRIX.json"
package_src="docs/standards/CHIO_COMPTROLLER_PARTNER_CONTRACT_PACKAGE.json"
package_snapshot="${output_root}/CHIO_COMPTROLLER_PARTNER_CONTRACT_PACKAGE.json"
contracts_src="docs/release/CHIO_COMPTROLLER_PARTNER_CONTRACTS.md"
contracts_snapshot="${output_root}/CHIO_COMPTROLLER_PARTNER_CONTRACTS.md"
cargo_target_dir="target/qualify-comptroller-partner-contracts-build"

rm -rf "${output_root}"
mkdir -p "${log_root}"

run_and_log() {
  local name="$1"
  shift
  local log_path="${log_root}/${name}.log"
  echo "==> ${name}"
  "$@" 2>&1 | tee "${log_path}"
}

python3 -m json.tool "${matrix_src}" >/dev/null
python3 -m json.tool "${package_src}" >/dev/null
cp "${matrix_src}" "${matrix_snapshot}"
cp "${package_src}" "${package_snapshot}"
cp "${contracts_src}" "${contracts_snapshot}"

export CARGO_TARGET_DIR="${cargo_target_dir}"

run_and_log receipt-checkpoint \
  cargo test -p chio-kernel --test retention archived_receipt_verifies_against_checkpoint
run_and_log liability-market \
  cargo test -p chio-cli --test receipt_query test_liability_market_quote_and_bind_workflow_surfaces -- --exact
run_and_log liability-claim \
  cargo test -p chio-cli --test receipt_query test_liability_claim_workflow_surfaces -- --exact
run_and_log underwriting-contract \
  cargo test -p chio-cli --test receipt_query test_underwriting_decision_issue_and_list_surfaces -- --exact
run_and_log credit-contract \
  cargo test -p chio-cli --test receipt_query test_credit_facility_report_issue_and_list_surfaces -- --exact
run_and_log capital-contract \
  cargo test -p chio-cli --test receipt_query test_capital_book_report_export_surfaces -- --exact

cat >"${report_path}" <<'EOF'
# Comptroller Partner-Contract Qualification

This bundle records the focused proof that Chio exposes partner-visible receipt,
checkpoint, settlement, underwriting, credit, capital, and liability contract
surfaces.

Decision:

- Chio qualifies locally for partner-visible receipt and settlement contracts.
- Governed receipts, checkpoints, settlement reconciliation, and signed
  economic artifacts are packaged as explicit review surfaces.
- Compatibility-only `allow_without_receipt` paths remain explicitly
  non-authoritative.

Still not proved:

- ecosystem-wide partner adoption
- economic dependence on Chio as an unavoidable settlement or billing authority

Executed command set:

- `cargo test -p chio-kernel --test retention archived_receipt_verifies_against_checkpoint`
- `cargo test -p chio-cli --test receipt_query test_liability_market_quote_and_bind_workflow_surfaces -- --exact`
- `cargo test -p chio-cli --test receipt_query test_liability_claim_workflow_surfaces -- --exact`
- `cargo test -p chio-cli --test receipt_query test_underwriting_decision_issue_and_list_surfaces -- --exact`
- `cargo test -p chio-cli --test receipt_query test_credit_facility_report_issue_and_list_surfaces -- --exact`
- `cargo test -p chio-cli --test receipt_query test_capital_book_report_export_surfaces -- --exact`

Supporting documents:

- `CHIO_PARTNER_RECEIPT_SETTLEMENT_CONTRACT_MATRIX.json`
- `CHIO_COMPTROLLER_PARTNER_CONTRACT_PACKAGE.json`
- `CHIO_COMPTROLLER_PARTNER_CONTRACTS.md`
EOF

python3 - <<'PY' "${output_root}" "${checksum_path}" "${manifest_path}"
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

output_root = Path(sys.argv[1])
checksum_path = Path(sys.argv[2])
manifest_path = Path(sys.argv[3])

entries = []
for artifact in sorted(output_root.rglob("*")):
    if not artifact.is_file():
        continue
    if artifact in {checksum_path, manifest_path}:
        continue
    payload = artifact.read_bytes()
    entries.append(
        {
            "path": artifact.relative_to(output_root).as_posix(),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
    )

checksum_path.write_text(
    "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries)
)

manifest = {
    "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "scope": "comptroller_partner_contract_qualification",
    "decision": "partner_contract_package_defined_and_exercised_locally",
    "claimLevel": "partner_receipt_settlement_contracts",
    "artifacts": entries,
}

manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
