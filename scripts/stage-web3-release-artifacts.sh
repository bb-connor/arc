#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "staging hosted web3 artifacts requires python3 on PATH" >&2
  exit 1
fi

dest_root="target/release-qualification/web3-runtime"
mkdir -p "${dest_root}"

present_list="$(mktemp "${TMPDIR:-/tmp}/arc-web3-present.XXXXXX")"
missing_list="$(mktemp "${TMPDIR:-/tmp}/arc-web3-missing.XXXXXX")"

cleanup() {
  rm -f "${present_list}" "${missing_list}"
}
trap cleanup EXIT

copy_if_exists() {
  local src="$1"
  local dest="$2"
  if [[ -e "${src}" ]]; then
    mkdir -p "$(dirname "${dest}")"
    cp "${src}" "${dest}"
    printf '%s\n' "${dest}" >>"${present_list}"
  else
    printf '%s\n' "${src}" >>"${missing_list}"
  fi
}

copy_if_exists \
  "target/web3-runtime-qualification/qualification.log" \
  "${dest_root}/logs/qualification.log"
copy_if_exists \
  "target/web3-ops-qualification/qualification.log" \
  "${dest_root}/logs/ops-qualification.log"
copy_if_exists \
  "target/web3-e2e-qualification/qualification.log" \
  "${dest_root}/logs/e2e-qualification.log"
copy_if_exists \
  "target/web3-promotion-qualification/qualification.log" \
  "${dest_root}/logs/promotion-qualification.log"
copy_if_exists \
  "contracts/deployments/local-devnet.json" \
  "${dest_root}/contracts/deployments/local-devnet.json"
copy_if_exists \
  "contracts/deployments/local-devnet.reviewed.json" \
  "${dest_root}/contracts/deployments/local-devnet.reviewed.json"
copy_if_exists \
  "contracts/deployments/base-mainnet.template.json" \
  "${dest_root}/contracts/deployments/base-mainnet.template.json"
copy_if_exists \
  "contracts/deployments/arbitrum-one.template.json" \
  "${dest_root}/contracts/deployments/arbitrum-one.template.json"
copy_if_exists \
  "contracts/reports/local-devnet-qualification.json" \
  "${dest_root}/contracts/reports/local-devnet-qualification.json"
copy_if_exists \
  "contracts/reports/ARC_WEB3_CONTRACT_SECURITY_REVIEW.md" \
  "${dest_root}/contracts/reports/ARC_WEB3_CONTRACT_SECURITY_REVIEW.md"
copy_if_exists \
  "contracts/reports/ARC_WEB3_CONTRACT_GAS_AND_STORAGE.md" \
  "${dest_root}/contracts/reports/ARC_WEB3_CONTRACT_GAS_AND_STORAGE.md"
copy_if_exists \
  "docs/release/ARC_WEB3_READINESS_AUDIT.md" \
  "${dest_root}/docs/release/ARC_WEB3_READINESS_AUDIT.md"
copy_if_exists \
  "docs/release/ARC_WEB3_DEPLOYMENT_PROMOTION.md" \
  "${dest_root}/docs/release/ARC_WEB3_DEPLOYMENT_PROMOTION.md"
copy_if_exists \
  "docs/release/ARC_WEB3_OPERATIONS_RUNBOOK.md" \
  "${dest_root}/docs/release/ARC_WEB3_OPERATIONS_RUNBOOK.md"
copy_if_exists \
  "docs/release/ARC_WEB3_PARTNER_PROOF.md" \
  "${dest_root}/docs/release/ARC_WEB3_PARTNER_PROOF.md"
copy_if_exists \
  "docs/standards/ARC_WEB3_OPERATIONS_PROFILE.md" \
  "${dest_root}/docs/standards/ARC_WEB3_OPERATIONS_PROFILE.md"
copy_if_exists \
  "docs/standards/ARC_WEB3_OPERATIONS_QUALIFICATION_MATRIX.json" \
  "${dest_root}/docs/standards/ARC_WEB3_OPERATIONS_QUALIFICATION_MATRIX.json"
copy_if_exists \
  "docs/standards/ARC_WEB3_DEPLOYMENT_POLICY.json" \
  "${dest_root}/docs/standards/ARC_WEB3_DEPLOYMENT_POLICY.json"
copy_if_exists \
  "docs/standards/ARC_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json" \
  "${dest_root}/docs/standards/ARC_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json"
copy_if_exists \
  "docs/standards/ARC_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json" \
  "${dest_root}/docs/standards/ARC_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json"
copy_if_exists \
  "docs/standards/ARC_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json" \
  "${dest_root}/docs/standards/ARC_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json"
copy_if_exists \
  "docs/standards/ARC_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json" \
  "${dest_root}/docs/standards/ARC_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json"
copy_if_exists \
  "target/web3-promotion-qualification/promotion-qualification.json" \
  "${dest_root}/promotion/promotion-qualification.json"
copy_if_exists \
  "target/web3-e2e-qualification/partner-qualification.json" \
  "${dest_root}/e2e/partner-qualification.json"
copy_if_exists \
  "target/web3-e2e-qualification/scenarios/fx-dual-sign-settlement.json" \
  "${dest_root}/e2e/scenarios/fx-dual-sign-settlement.json"
copy_if_exists \
  "target/web3-e2e-qualification/scenarios/timeout-refund-recovery.json" \
  "${dest_root}/e2e/scenarios/timeout-refund-recovery.json"
copy_if_exists \
  "target/web3-e2e-qualification/scenarios/reorg-recovery.json" \
  "${dest_root}/e2e/scenarios/reorg-recovery.json"
copy_if_exists \
  "target/web3-e2e-qualification/scenarios/bond-impair-recovery.json" \
  "${dest_root}/e2e/scenarios/bond-impair-recovery.json"
copy_if_exists \
  "target/web3-e2e-qualification/scenarios/bond-expiry-recovery.json" \
  "${dest_root}/e2e/scenarios/bond-expiry-recovery.json"
copy_if_exists \
  "target/web3-ops-qualification/runtime-reports/arc-link-runtime-report.json" \
  "${dest_root}/ops/runtime-reports/arc-link-runtime-report.json"
copy_if_exists \
  "target/web3-ops-qualification/runtime-reports/arc-anchor-runtime-report.json" \
  "${dest_root}/ops/runtime-reports/arc-anchor-runtime-report.json"
copy_if_exists \
  "target/web3-ops-qualification/runtime-reports/arc-settle-runtime-report.json" \
  "${dest_root}/ops/runtime-reports/arc-settle-runtime-report.json"
copy_if_exists \
  "target/web3-ops-qualification/control-state/arc-link-control-state.json" \
  "${dest_root}/ops/control-state/arc-link-control-state.json"
copy_if_exists \
  "target/web3-ops-qualification/control-state/arc-anchor-control-state.json" \
  "${dest_root}/ops/control-state/arc-anchor-control-state.json"
copy_if_exists \
  "target/web3-ops-qualification/control-state/arc-settle-control-state.json" \
  "${dest_root}/ops/control-state/arc-settle-control-state.json"
copy_if_exists \
  "target/web3-ops-qualification/control-traces/arc-link-control-trace.json" \
  "${dest_root}/ops/control-traces/arc-link-control-trace.json"
copy_if_exists \
  "target/web3-ops-qualification/control-traces/arc-anchor-control-trace.json" \
  "${dest_root}/ops/control-traces/arc-anchor-control-trace.json"
copy_if_exists \
  "target/web3-ops-qualification/control-traces/arc-settle-control-trace.json" \
  "${dest_root}/ops/control-traces/arc-settle-control-trace.json"
copy_if_exists \
  "target/web3-ops-qualification/incident-audit.json" \
  "${dest_root}/ops/incident-audit.json"
copy_if_exists \
  "target/web3-promotion-qualification/run-a/approval.json" \
  "${dest_root}/promotion/run-a/approval.json"
copy_if_exists \
  "target/web3-promotion-qualification/run-a/promotion-report.json" \
  "${dest_root}/promotion/run-a/promotion-report.json"
copy_if_exists \
  "target/web3-promotion-qualification/run-a/rollback-plan.json" \
  "${dest_root}/promotion/run-a/rollback-plan.json"
copy_if_exists \
  "target/web3-promotion-qualification/run-a/deployment.json" \
  "${dest_root}/promotion/run-a/deployment.json"
copy_if_exists \
  "target/web3-promotion-qualification/run-b/promotion-report.json" \
  "${dest_root}/promotion/run-b/promotion-report.json"
copy_if_exists \
  "target/web3-promotion-qualification/negative-approval/promotion-report.json" \
  "${dest_root}/promotion/negative-approval/promotion-report.json"
copy_if_exists \
  "target/web3-promotion-qualification/negative-rollback/promotion-report.json" \
  "${dest_root}/promotion/negative-rollback/promotion-report.json"
copy_if_exists \
  "target/web3-promotion-qualification/negative-rollback/rollback-plan.json" \
  "${dest_root}/promotion/negative-rollback/rollback-plan.json"

python3 - <<'PY' "${dest_root}/artifact-manifest.json" "${present_list}" "${missing_list}"
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

manifest_path = Path(sys.argv[1])
present_path = Path(sys.argv[2])
missing_path = Path(sys.argv[3])

def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]

manifest = {
    "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "source": "github-actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "local",
    "candidateSha": os.environ.get("GITHUB_SHA", "local"),
    "workflowRunId": os.environ.get("GITHUB_RUN_ID"),
    "workflowRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    "presentArtifacts": read_lines(present_path),
    "missingArtifacts": read_lines(missing_path),
}

manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
