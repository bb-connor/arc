#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1; then
  echo "comptroller operator-surface qualification requires cargo on PATH" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "comptroller operator-surface qualification requires python3 on PATH" >&2
  exit 1
fi

output_root="target/release-qualification/comptroller-operator-surfaces"
log_root="${output_root}/logs"
manifest_path="${output_root}/artifact-manifest.json"
checksum_path="${output_root}/SHA256SUMS"
report_path="${output_root}/qualification-report.md"
profile_src="docs/standards/ARC_OPERATOR_CONTROL_SURFACE_PROFILE.json"
profile_snapshot="${output_root}/ARC_OPERATOR_CONTROL_SURFACE_PROFILE.json"
runbook_src="docs/release/ARC_COMPTROLLER_OPERATOR_RUNBOOK.md"
runbook_snapshot="${output_root}/ARC_COMPTROLLER_OPERATOR_RUNBOOK.md"
cargo_target_dir="target/qualify-comptroller-operator-surfaces-build"

rm -rf "${output_root}"
mkdir -p "${log_root}"

run_and_log() {
  local name="$1"
  shift
  local log_path="${log_root}/${name}.log"
  echo "==> ${name}"
  "$@" 2>&1 | tee "${log_path}"
}

python3 -m json.tool "${profile_src}" >/dev/null
cp "${profile_src}" "${profile_snapshot}"
cp "${runbook_src}" "${runbook_snapshot}"

export CARGO_TARGET_DIR="${cargo_target_dir}"

run_and_log operator-report \
  cargo test -p arc-cli --test receipt_query test_operator_report_endpoint -- --exact
run_and_log settlement-reconciliation \
  cargo test -p arc-cli --test receipt_query test_settlement_reconciliation_report_and_action_endpoint -- --exact
run_and_log metered-billing \
  cargo test -p arc-cli --test receipt_query test_metered_billing_reconciliation_report_and_action_endpoint -- --exact
run_and_log authorization-context \
  cargo test -p arc-cli --test receipt_query test_authorization_context_report_and_cli -- --exact
run_and_log underwriting-surface \
  cargo test -p arc-cli --test receipt_query test_underwriting_decision_issue_and_list_surfaces -- --exact
run_and_log credit-surface \
  cargo test -p arc-cli --test receipt_query test_credit_facility_report_issue_and_list_surfaces -- --exact
run_and_log capital-surface \
  cargo test -p arc-cli --test receipt_query test_capital_book_report_export_surfaces -- --exact

cat >"${report_path}" <<'EOF'
# Comptroller Operator-Surface Qualification

This bundle records the focused post-v3.16 proof that ARC exposes explicit
operator-facing economic control surfaces rather than only crate-internal
comptroller primitives.

Decision:

- ARC qualifies locally for operator-facing economic control surfaces.
- The trust-control service exposes report and action endpoints over governed
  operator evidence, settlement reconciliation, metered billing
  reconciliation, and authorization-context review.
- Signed underwriting, credit, capital, and liability artifacts are available
  through explicit trust-control issuance surfaces.

Still not proved:

- independent third-party operators running these surfaces in production
- partner economic dependence on ARC as a market control layer

Executed command set:

- `cargo test -p arc-cli --test receipt_query test_operator_report_endpoint -- --exact`
- `cargo test -p arc-cli --test receipt_query test_settlement_reconciliation_report_and_action_endpoint -- --exact`
- `cargo test -p arc-cli --test receipt_query test_metered_billing_reconciliation_report_and_action_endpoint -- --exact`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_and_cli -- --exact`
- `cargo test -p arc-cli --test receipt_query test_underwriting_decision_issue_and_list_surfaces -- --exact`
- `cargo test -p arc-cli --test receipt_query test_credit_facility_report_issue_and_list_surfaces -- --exact`
- `cargo test -p arc-cli --test receipt_query test_capital_book_report_export_surfaces -- --exact`

Supporting documents:

- `ARC_OPERATOR_CONTROL_SURFACE_PROFILE.json`
- `ARC_COMPTROLLER_OPERATOR_RUNBOOK.md`
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
    "scope": "comptroller_operator_surface_qualification",
    "decision": "externally_operable_control_surfaces_defined_and_exercised_locally",
    "claimLevel": "operator_control_surfaces",
    "artifacts": entries,
}

manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
