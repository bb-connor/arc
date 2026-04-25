#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "staging hosted web3 artifacts requires python3 on PATH" >&2
  exit 1
fi

dest_root="target/release-qualification/web3-runtime"
mkdir -p "${dest_root}"

present_list="$(mktemp "${TMPDIR:-/tmp}/chio-web3-present.XXXXXX")"
missing_list="$(mktemp "${TMPDIR:-/tmp}/chio-web3-missing.XXXXXX")"

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
  "target/web3-example-qualification/qualification.log" \
  "${dest_root}/logs/example-qualification.log"
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
  "contracts/deployments/base-sepolia.template.json" \
  "${dest_root}/contracts/deployments/base-sepolia.template.json"
copy_if_exists \
  "contracts/deployments/arbitrum-one.template.json" \
  "${dest_root}/contracts/deployments/arbitrum-one.template.json"
copy_if_exists \
  "contracts/reports/local-devnet-qualification.json" \
  "${dest_root}/contracts/reports/local-devnet-qualification.json"
copy_if_exists \
  "contracts/reports/CHIO_WEB3_CONTRACT_SECURITY_REVIEW.md" \
  "${dest_root}/contracts/reports/CHIO_WEB3_CONTRACT_SECURITY_REVIEW.md"
copy_if_exists \
  "contracts/reports/CHIO_WEB3_CONTRACT_GAS_AND_STORAGE.md" \
  "${dest_root}/contracts/reports/CHIO_WEB3_CONTRACT_GAS_AND_STORAGE.md"
copy_if_exists \
  "docs/release/CHIO_WEB3_READINESS_AUDIT.md" \
  "${dest_root}/docs/release/CHIO_WEB3_READINESS_AUDIT.md"
copy_if_exists \
  "docs/release/CHIO_WEB3_DEPLOYMENT_PROMOTION.md" \
  "${dest_root}/docs/release/CHIO_WEB3_DEPLOYMENT_PROMOTION.md"
copy_if_exists \
  "docs/release/CHIO_WEB3_MAINNET_CUTOVER_CHECKLIST.md" \
  "${dest_root}/docs/release/CHIO_WEB3_MAINNET_CUTOVER_CHECKLIST.md"
copy_if_exists \
  "docs/release/CHIO_WEB3_OPERATIONS_RUNBOOK.md" \
  "${dest_root}/docs/release/CHIO_WEB3_OPERATIONS_RUNBOOK.md"
copy_if_exists \
  "docs/release/CHIO_WEB3_PARTNER_PROOF.md" \
  "${dest_root}/docs/release/CHIO_WEB3_PARTNER_PROOF.md"
copy_if_exists \
  "docs/standards/CHIO_WEB3_OPERATIONS_PROFILE.md" \
  "${dest_root}/docs/standards/CHIO_WEB3_OPERATIONS_PROFILE.md"
copy_if_exists \
  "docs/standards/CHIO_WEB3_OPERATIONS_QUALIFICATION_MATRIX.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_OPERATIONS_QUALIFICATION_MATRIX.json"
copy_if_exists \
  "docs/standards/CHIO_WEB3_DEPLOYMENT_POLICY.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_DEPLOYMENT_POLICY.json"
copy_if_exists \
  "docs/standards/CHIO_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json"
copy_if_exists \
  "docs/standards/CHIO_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json"
copy_if_exists \
  "docs/standards/CHIO_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json"
copy_if_exists \
  "docs/standards/CHIO_WEB3_OPERATOR_ENVIRONMENT.example" \
  "${dest_root}/docs/standards/CHIO_WEB3_OPERATOR_ENVIRONMENT.example"
copy_if_exists \
  "docs/standards/CHIO_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json"
copy_if_exists \
  "target/web3-promotion-qualification/review-prep/qualification.json" \
  "${dest_root}/promotion/review-prep/qualification.json"
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
  "target/web3-ops-qualification/runtime-reports/chio-link-runtime-report.json" \
  "${dest_root}/ops/runtime-reports/chio-link-runtime-report.json"
copy_if_exists \
  "target/web3-ops-qualification/runtime-reports/chio-anchor-runtime-report.json" \
  "${dest_root}/ops/runtime-reports/chio-anchor-runtime-report.json"
copy_if_exists \
  "target/web3-ops-qualification/runtime-reports/chio-settle-runtime-report.json" \
  "${dest_root}/ops/runtime-reports/chio-settle-runtime-report.json"
copy_if_exists \
  "target/web3-ops-qualification/control-state/chio-link-control-state.json" \
  "${dest_root}/ops/control-state/chio-link-control-state.json"
copy_if_exists \
  "target/web3-ops-qualification/control-state/chio-anchor-control-state.json" \
  "${dest_root}/ops/control-state/chio-anchor-control-state.json"
copy_if_exists \
  "target/web3-ops-qualification/control-state/chio-settle-control-state.json" \
  "${dest_root}/ops/control-state/chio-settle-control-state.json"
copy_if_exists \
  "target/web3-ops-qualification/control-traces/chio-link-control-trace.json" \
  "${dest_root}/ops/control-traces/chio-link-control-trace.json"
copy_if_exists \
  "target/web3-ops-qualification/control-traces/chio-anchor-control-trace.json" \
  "${dest_root}/ops/control-traces/chio-anchor-control-trace.json"
copy_if_exists \
  "target/web3-ops-qualification/control-traces/chio-settle-control-trace.json" \
  "${dest_root}/ops/control-traces/chio-settle-control-trace.json"
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
copy_if_exists \
  "target/web3-live-rollout/base-sepolia/promotion/deployment.json" \
  "${dest_root}/live/base-sepolia/promotion/deployment.json"
copy_if_exists \
  "target/web3-live-rollout/base-sepolia/promotion/promotion-report.json" \
  "${dest_root}/live/base-sepolia/promotion/promotion-report.json"
copy_if_exists \
  "target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json" \
  "${dest_root}/live/base-sepolia/base-sepolia-smoke.json"
copy_if_exists \
  "target/web3-example-qualification/internet-of-agents-web3-network/review-result.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/review-result.json"
copy_if_exists \
  "target/web3-example-qualification/internet-of-agents-web3-network/summary.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/summary.json"
copy_if_exists \
  "target/web3-example-qualification/internet-of-agents-web3-network/web3/validation-index.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/web3/validation-index.json"
copy_if_exists \
  "target/web3-example-qualification/internet-of-agents-web3-network/evidence/cutover-readiness.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/evidence/cutover-readiness.json"
copy_if_exists \
  "target/web3-example-qualification/internet-of-agents-web3-network/contracts/settlement-packet.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/contracts/settlement-packet.json"
copy_if_exists \
  "target/web3-example-qualification/internet-of-agents-web3-network/contracts/web3-settlement-dispatch.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/contracts/web3-settlement-dispatch.json"
copy_if_exists \
  "target/web3-example-qualification/internet-of-agents-web3-network/contracts/web3-settlement-receipt.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/contracts/web3-settlement-receipt.json"
copy_if_exists \
  "target/web3-example-qualification/internet-of-agents-web3-network/bundle-manifest.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/bundle-manifest.json"

example_root="target/web3-example-qualification/internet-of-agents-web3-network"
example_dest="${dest_root}/examples/internet-of-agents-web3-network"
for artifact in \
  "chio/topology.json" \
  "chio/receipts/receipt-summary.json" \
  "chio/receipts/trust-control.json" \
  "chio/receipts/market-api-sidecar.json" \
  "chio/receipts/settlement-api-sidecar.json" \
  "chio/receipts/provider-review-mcp.json" \
  "chio/receipts/subcontractor-review-mcp.json" \
  "chio/receipts/web3-evidence-mcp.json" \
  "chio/receipts/budget.json" \
  "chio/receipts/approval.json" \
  "chio/receipts/rail-selection.json" \
  "chio/budgets/budget-summary.json" \
  "chio/budgets/quote-exposure-authorization.json" \
  "chio/budgets/settlement-spend-reconciliation.json" \
  "identity/passports/proofworks-provider-passport.json" \
  "identity/passports/proofworks-provider-passport-provenance.json" \
  "identity/passports/proofworks-provider-passport-verdict.json" \
  "identity/passports/provider-passport-verdicts.json" \
  "identity/passports/cipherworks-subcontractor-passport.json" \
  "identity/presentations/provider-challenge.json" \
  "identity/presentations/provider-presentation.json" \
  "identity/presentations/provider-presentation-verdict.json" \
  "identity/presentations/subcontractor-challenge.json" \
  "identity/presentations/subcontractor-presentation.json" \
  "identity/runtime-appraisals/treasury-agent.json" \
  "identity/runtime-appraisals/procurement-agent.json" \
  "identity/runtime-appraisals/provider-agent.json" \
  "identity/runtime-appraisals/subcontractor-agent.json" \
  "identity/runtime-appraisals/settlement-agent.json" \
  "identity/runtime-appraisals/auditor-agent.json" \
  "identity/runtime-degradation/capability-denial.json" \
  "identity/runtime-degradation/provider-quarantine.json" \
  "identity/runtime-degradation/reattestation.json" \
  "identity/runtime-degradation/readmission.json" \
  "identity/runtime-degradation/summary.json" \
  "federation/bilateral-evidence-policy.json" \
  "federation/evidence-export.json" \
  "federation/evidence-export-package/manifest.json" \
  "federation/evidence-import.json" \
  "federation/federated-delegation-policy.json" \
  "federation/open-admission-evaluation.json" \
  "federation/federated-provider-capability.json" \
  "federation/provider-admission-verdicts.json" \
  "federation/subcontractor-admission.json" \
  "reputation/history-ledger.json" \
  "reputation/provider-scorecards.json" \
  "reputation/passport-drift-report.json" \
  "reputation/provider-local-report.json" \
  "reputation/provider-passport-comparison.json" \
  "reputation/provider-reputation-verdict.json" \
  "behavior/behavioral-feed.json" \
  "behavior/baseline.json" \
  "behavior/behavioral-status.json" \
  "guardrails/invalid-spiffe-denial.json" \
  "guardrails/overspend-denial.json" \
  "guardrails/velocity-burst-denial.json" \
  "adversarial/prompt_injection-denial.json" \
  "adversarial/invoice_tampering-denial.json" \
  "adversarial/quote_replay-denial.json" \
  "adversarial/expired_capability-denial.json" \
  "adversarial/unauthorized_settlement_route-denial.json" \
  "adversarial/forged_passport-denial.json" \
  "adversarial/summary.json" \
  "approvals/high-risk-release-challenge.json" \
  "approvals/high-risk-release-decision.json" \
  "approvals/high-risk-release-receipt.json" \
  "approvals/high-risk-release-audit.json" \
  "payments/x402-payment-required.json" \
  "payments/chio-payment-proof.json" \
  "payments/x402-payment-satisfaction.json" \
  "subcontracting/delegated-capability.json" \
  "subcontracting/inherited-obligations.json" \
  "subcontracting/review-request.json" \
  "subcontracting/review-attestation.json" \
  "settlement/rail-selection.json" \
  "disputes/weak-deliverable.json" \
  "disputes/partial-payment.json" \
  "disputes/refund.json" \
  "disputes/reputation-downgrade.json" \
  "disputes/passport-claim-drift.json" \
  "disputes/remediation-packet.json" \
  "disputes/dispute-packet.json" \
  "disputes/dispute-audit.json" \
  "disputes/dispute-summary.json" \
  "operations/trace-map.json" \
  "operations/siem-events.json" \
  "operations/observability-status.json" \
  "operations/operations-timeline.json" \
  "market/rfq-request.json" \
  "market/provider-bids.json" \
  "market/provider-selection.json" \
  "provider/review-result.json" \
  "provider/review-attestation.json" \
  "provider/reputation-evaluation.json"; do
  copy_if_exists "${example_root}/${artifact}" "${example_dest}/${artifact}"
done

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
