"""Offline verification for the internet-of-agents web3 example."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

REQUIRED = [
    "identities/public-identities.json",
    "capabilities/root-treasury.json",
    "capabilities/procurement-agent.json",
    "capabilities/provider-agent.json",
    "capabilities/subcontractor-agent.json",
    "capabilities/settlement-agent.json",
    "capabilities/auditor-agent.json",
    "capabilities/sidecar-client.json",
    "chio/topology.json",
    "chio/capabilities/root-treasury.json",
    "chio/capabilities/procurement-agent.json",
    "chio/capabilities/provider-agent.json",
    "chio/capabilities/subcontractor-agent.json",
    "chio/capabilities/settlement-agent.json",
    "chio/capabilities/auditor-agent.json",
    "chio/capabilities/sidecar-client.json",
    "chio/receipts/receipt-summary.json",
    "chio/receipts/trust-control.json",
    "chio/receipts/market-api-sidecar.json",
    "chio/receipts/settlement-api-sidecar.json",
    "chio/receipts/web3-evidence-mcp.json",
    "chio/receipts/provider-review-mcp.json",
    "chio/receipts/subcontractor-review-mcp.json",
    "chio/receipts/budget.json",
    "chio/receipts/approval.json",
    "chio/receipts/rail-selection.json",
    "chio/budgets/quote-exposure-authorization.json",
    "chio/budgets/settlement-spend-reconciliation.json",
    "chio/budgets/budget-summary.json",
    "identity/passports/proofworks-provider-passport.json",
    "identity/passports/proofworks-provider-passport-provenance.json",
    "identity/passports/proofworks-provider-passport-verdict.json",
    "identity/passports/provider-passport-verdicts.json",
    "identity/passports/cipherworks-subcontractor-passport.json",
    "identity/presentations/provider-challenge.json",
    "identity/presentations/provider-presentation.json",
    "identity/presentations/provider-presentation-verdict.json",
    "identity/presentations/subcontractor-challenge.json",
    "identity/presentations/subcontractor-presentation.json",
    "identity/runtime-appraisals/treasury-agent.json",
    "identity/runtime-appraisals/procurement-agent.json",
    "identity/runtime-appraisals/provider-agent.json",
    "identity/runtime-appraisals/subcontractor-agent.json",
    "identity/runtime-appraisals/settlement-agent.json",
    "identity/runtime-appraisals/auditor-agent.json",
    "identity/runtime-degradation/capability-denial.json",
    "identity/runtime-degradation/provider-quarantine.json",
    "identity/runtime-degradation/reattestation.json",
    "identity/runtime-degradation/readmission.json",
    "identity/runtime-degradation/summary.json",
    "federation/bilateral-evidence-policy.json",
    "federation/evidence-export.json",
    "federation/evidence-export-package/manifest.json",
    "federation/evidence-import.json",
    "federation/federated-delegation-policy.json",
    "federation/open-admission-evaluation.json",
    "federation/federated-provider-capability.json",
    "federation/provider-admission-verdicts.json",
    "federation/subcontractor-admission.json",
    "reputation/history-ledger.json",
    "reputation/provider-scorecards.json",
    "reputation/passport-drift-report.json",
    "reputation/provider-local-report.json",
    "reputation/provider-passport-comparison.json",
    "reputation/provider-reputation-verdict.json",
    "behavior/behavioral-feed.json",
    "behavior/baseline.json",
    "behavior/behavioral-status.json",
    "guardrails/invalid-spiffe-denial.json",
    "guardrails/overspend-denial.json",
    "guardrails/velocity-burst-denial.json",
    "adversarial/prompt_injection-denial.json",
    "adversarial/invoice_tampering-denial.json",
    "adversarial/quote_replay-denial.json",
    "adversarial/expired_capability-denial.json",
    "adversarial/unauthorized_settlement_route-denial.json",
    "adversarial/forged_passport-denial.json",
    "adversarial/summary.json",
    "approvals/high-risk-release-challenge.json",
    "approvals/high-risk-release-decision.json",
    "approvals/high-risk-release-receipt.json",
    "approvals/high-risk-release-audit.json",
    "payments/x402-payment-required.json",
    "payments/chio-payment-proof.json",
    "payments/x402-payment-satisfaction.json",
    "subcontracting/delegated-capability.json",
    "subcontracting/inherited-obligations.json",
    "subcontracting/review-request.json",
    "subcontracting/review-attestation.json",
    "settlement/rail-selection.json",
    "disputes/weak-deliverable.json",
    "disputes/partial-payment.json",
    "disputes/refund.json",
    "disputes/reputation-downgrade.json",
    "disputes/passport-claim-drift.json",
    "disputes/remediation-packet.json",
    "disputes/dispute-packet.json",
    "disputes/dispute-audit.json",
    "disputes/dispute-summary.json",
    "operations/trace-map.json",
    "operations/siem-events.json",
    "operations/operations-timeline.json",
    "operations/observability-status.json",
    "provider/review-attestation.json",
    "provider/review-result.json",
    "agents/treasury-output.json",
    "agents/procurement-output.json",
    "agents/provider-output.json",
    "agents/subcontractor-output.json",
    "agents/settlement-output.json",
    "agents/auditor-output.json",
    "scenario/order-request.json",
    "scenario/provider-catalog.json",
    "scenario/timeline.json",
    "scenario/treasury-policy.json",
    "market/quote-request.json",
    "market/rfq-request.json",
    "market/provider-bids.json",
    "market/provider-selection.json",
    "market/quote-response.json",
    "market/fulfillment-package.json",
    "contracts/settlement-packet.json",
    "contracts/service-order.json",
    "contracts/web3-settlement-dispatch.json",
    "contracts/web3-settlement-receipt.json",
    "evidence/cutover-readiness.json",
    "financial/settlement-reconciliation.json",
    "lineage/root-treasury-chain.json",
    "lineage/procurement-agent-chain.json",
    "lineage/provider-agent-chain.json",
    "lineage/subcontractor-agent-chain.json",
    "lineage/settlement-agent-chain.json",
    "lineage/auditor-agent-chain.json",
    "web3/e2e-partner-qualification.json",
    "web3/promotion-qualification.json",
    "web3/ops-incident-audit.json",
    "web3/x402-requirements-example.json",
    "web3/validation-index.json",
    "summary.json",
    "bundle-manifest.json",
]

REQUIRED_BASE_SEPOLIA_TX_IDS = {
    "identity.operator_registration",
    "identity.entity_registration",
    "anchor.partial_root_publish",
    "anchor.final_root_publish",
    "settlement.usdc_approval",
    "settlement.primary_escrow_create",
    "settlement.partial_release",
    "settlement.final_release",
    "settlement.refund_escrow_create",
    "settlement.timeout_refund",
}


def _load(path: Path) -> Any:
    return json.loads(path.read_text())


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_signature(public_key: str, body: dict[str, Any], signature: str) -> bool:
    try:
        VerifyKey(public_key, encoder=HexEncoder).verify(_canonical(body), bytes.fromhex(signature))
        return True
    except (BadSignatureError, ValueError):
        return False


def _require_source(
    *,
    label: str,
    artifact: dict[str, Any],
    expected: str | set[str],
    errors: list[str],
) -> None:
    source = artifact.get("source")
    if isinstance(expected, str):
        accepted = {expected}
    else:
        accepted = expected
    if source not in accepted:
        accepted_text = ", ".join(sorted(accepted))
        errors.append(f"{label} must prove source {accepted_text}, got {source!r}")


def _cap_body(cap: dict[str, Any]) -> dict[str, Any]:
    body = {
        "id": cap["id"],
        "issuer": cap["issuer"],
        "subject": cap["subject"],
        "scope": cap["scope"],
        "issued_at": cap["issued_at"],
        "expires_at": cap["expires_at"],
    }
    if cap.get("delegation_chain"):
        body["delegation_chain"] = cap["delegation_chain"]
    return body


def _link_body(link: dict[str, Any]) -> dict[str, Any]:
    return {
        "capability_id": link["capability_id"],
        "delegator": link["delegator"],
        "delegatee": link["delegatee"],
        "attenuations": link["attenuations"],
        "timestamp": link["timestamp"],
    }


def _check_manifest(bundle: Path, errors: list[str]) -> dict[str, Any]:
    manifest = _load(bundle / "bundle-manifest.json")
    verified = []
    for rel, expected in manifest.get("sha256", {}).items():
        path = bundle / rel
        if not path.exists():
            errors.append(f"manifest missing file: {rel}")
            continue
        if _sha256_file(path) != expected:
            errors.append(f"manifest hash mismatch: {rel}")
            continue
        verified.append(rel)
    return {"verified_files": verified, "manifest_entries": len(manifest.get("sha256", {}))}


def _check_capabilities(bundle: Path, errors: list[str]) -> dict[str, Any]:
    cap_names = [
        "root-treasury",
        "procurement-agent",
        "provider-agent",
        "subcontractor-agent",
        "settlement-agent",
        "auditor-agent",
    ]
    caps = {name: _load(bundle / "capabilities" / f"{name}.json") for name in cap_names}
    by_id = {cap["id"]: cap for cap in caps.values()}
    results = {}
    for name, cap in caps.items():
        trust_control_issued_root = name == "root-treasury" and cap.get("issuer") != cap.get("subject")
        verified = trust_control_issued_root or _verify_signature(
            cap["issuer"],
            _cap_body(cap),
            cap.get("signature", ""),
        )
        if not verified:
            errors.append(f"capability signature mismatch: {name}")
        chain = cap.get("delegation_chain", [])
        if name == "root-treasury":
            if chain:
                errors.append("root treasury capability must not have a delegation chain")
            results[name] = {"depth": 0}
            continue
        if not chain:
            errors.append(f"delegated capability missing chain: {name}")
            results[name] = {"depth": 0}
            continue
        last = chain[-1]
        parent = by_id.get(last.get("capability_id"))
        if not parent:
            errors.append(f"missing parent capability for {name}")
        if not _verify_signature(last["delegator"], _link_body(last), last.get("signature", "")):
            errors.append(f"delegation link signature mismatch: {name}")
        if last.get("delegatee") != cap.get("subject"):
            errors.append(f"delegation subject mismatch: {name}")
        if parent and cap.get("expires_at", 0) > parent.get("expires_at", 0):
            errors.append(f"delegated capability outlives parent: {name}")
        results[name] = {"depth": len(chain), "parent_id": last.get("capability_id")}
    return results


def _check_chio(bundle: Path, errors: list[str]) -> dict[str, Any]:
    topology = _load(bundle / "chio/topology.json")
    receipt_summary = _load(bundle / "chio/receipts/receipt-summary.json")
    budget_summary = _load(bundle / "chio/budgets/budget-summary.json")
    passport = _load(bundle / "identity/passports/proofworks-provider-passport.json")
    passport_provenance = _load(bundle / "identity/passports/proofworks-provider-passport-provenance.json")
    passport_cli_verdict = _load(bundle / "identity/passports/proofworks-provider-passport-verdict.json")
    passport_verdict = _load(bundle / "identity/presentations/provider-presentation-verdict.json")
    reputation_report = _load(bundle / "reputation/provider-local-report.json")
    reputation_comparison = _load(bundle / "reputation/provider-passport-comparison.json")
    federation_verdict = _load(bundle / "federation/open-admission-evaluation.json")
    federation_policy = _load(bundle / "federation/bilateral-evidence-policy.json")
    federation_export = _load(bundle / "federation/evidence-export.json")
    federation_import = _load(bundle / "federation/evidence-import.json")
    federated_capability = _load(bundle / "federation/federated-provider-capability.json")
    reputation_verdict = _load(bundle / "reputation/provider-reputation-verdict.json")
    provider_selection = _load(bundle / "market/provider-selection.json")
    subcontractor = _load(bundle / "subcontracting/delegated-capability.json")
    subcontractor_admission = _load(bundle / "federation/subcontractor-admission.json")
    runtime_degradation = _load(bundle / "identity/runtime-degradation/summary.json")
    observability = _load(bundle / "operations/observability-status.json")
    adversarial = _load(bundle / "adversarial/summary.json")
    behavior_status = _load(bundle / "behavior/behavioral-status.json")
    guardrails = {
        "invalid_spiffe": _load(bundle / "guardrails/invalid-spiffe-denial.json"),
        "overspend": _load(bundle / "guardrails/overspend-denial.json"),
        "velocity": _load(bundle / "guardrails/velocity-burst-denial.json"),
    }
    provider_review = _load(bundle / "provider/review-result.json")

    _require_source(
        label="provider passport provenance",
        artifact=passport_provenance,
        expected="chio-cli",
        errors=errors,
    )
    _require_source(
        label="provider passport verdict",
        artifact=passport_cli_verdict,
        expected="chio-cli",
        errors=errors,
    )
    _require_source(
        label="provider presentation verdict",
        artifact=passport_verdict,
        expected="chio-cli",
        errors=errors,
    )
    _require_source(
        label="provider reputation report",
        artifact=reputation_report,
        expected="chio-cli",
        errors=errors,
    )
    _require_source(
        label="provider reputation comparison",
        artifact=reputation_comparison,
        expected="chio-cli",
        errors=errors,
    )
    _require_source(
        label="provider reputation verdict",
        artifact=reputation_verdict,
        expected="chio-cli",
        errors=errors,
    )
    _require_source(
        label="federation evidence export",
        artifact=federation_export,
        expected="chio-cli",
        errors=errors,
    )
    _require_source(
        label="federation evidence import",
        artifact=federation_import,
        expected="chio-trust-control",
        errors=errors,
    )
    _require_source(
        label="federation admission",
        artifact=federation_verdict,
        expected="chio-trust-control",
        errors=errors,
    )
    _require_source(
        label="federated provider capability",
        artifact=federated_capability,
        expected="chio-trust-control",
        errors=errors,
    )
    provenance_commands = passport_provenance.get("commands", {})
    for command_id in [
        "passportCreate",
        "passportVerify",
        "challengeCreate",
        "challengeRespond",
        "challengeVerify",
    ]:
        if not provenance_commands.get(command_id):
            errors.append(f"provider passport provenance missing Chio command: {command_id}")
    if not passport.get("credentials"):
        errors.append("provider passport is not a Chio credential passport")
    if not (federation_policy.get("signature") or federation_policy.get("body", {}).get("signature")):
        errors.append("federation evidence policy missing Chio signature material")
    if not federation_export.get("commandResult", {}).get("command"):
        errors.append("federation evidence export missing Chio command result")
    if not federation_import.get("commandResult"):
        errors.append("federation evidence import missing trust-control result")
    if not federation_verdict.get("commandResult"):
        errors.append("federation admission missing trust-control federated-issue result")

    if topology.get("directUnmediatedDefaultPath") is not False:
        errors.append("Chio topology allows a direct unmediated default path")
    if len(topology.get("organizations", [])) != 4:
        errors.append("Chio topology must include four organizations")
    if any(not edge.get("url") for edge in topology.get("mcpEdges", [])):
        errors.append("Chio MCP edge URL missing")
    if any(not sidecar.get("url") for sidecar in topology.get("apiSidecars", [])):
        errors.append("Chio API sidecar URL missing")
    if receipt_summary.get("receiptCompleteness") != "pass":
        errors.append("Chio receipt completeness failed")
    for boundary, count in receipt_summary.get("boundaries", {}).items():
        if count <= 0:
            errors.append(f"Chio boundary has no receipt expectation: {boundary}")
    if budget_summary.get("authorizationStatus") != "authorized":
        errors.append("Chio budget exposure was not authorized")
    if budget_summary.get("reconciliationStatus") != "reconciled":
        errors.append("Chio budget spend was not reconciled")
    if passport_verdict.get("verdict") != "pass":
        errors.append("passport presentation verdict failed")
    if federation_verdict.get("verdict") != "pass":
        errors.append("federation admission verdict failed")
    if reputation_verdict.get("verdict") != "pass":
        errors.append("provider reputation verdict failed")
    if behavior_status.get("verdict") != "pass":
        errors.append("behavioral baseline verdict failed")
    if provider_review.get("verdict") != "pass":
        errors.append("provider review verdict failed")
    if provider_selection.get("status") != "pass":
        errors.append("RFQ provider selection failed")
    if provider_selection.get("selected_provider_id") != "proofworks-agent-auditors":
        errors.append("RFQ selected the wrong provider")
    if len(provider_selection.get("rejected_providers", [])) != 2:
        errors.append("RFQ must reject exactly two losing providers")
    if len(subcontractor.get("delegation_chain", [])) != 2:
        errors.append("subcontractor capability must have two-hop lineage")
    if subcontractor_admission.get("verdict") != "pass":
        errors.append("subcontractor federation admission failed")
    if runtime_degradation.get("status") != "quarantined_then_reattested":
        errors.append("runtime degradation did not quarantine then re-attest")
    if observability.get("status") != "correlated" or observability.get("all_events_have_receipts") is not True:
        errors.append("observability events are not receipt-correlated")
    for control, status in adversarial.get("controls", {}).items():
        if status != "denied":
            errors.append(f"adversarial control did not deny: {control}")
    for name, artifact in guardrails.items():
        if artifact.get("denied") is not True:
            errors.append(f"guardrail control did not deny: {name}")
        if artifact.get("receipt", {}).get("decision") != "deny":
            errors.append(f"guardrail control did not emit denial receipt: {name}")

    return {
        "mediation": "pass",
        "receipt_counts_by_boundary": receipt_summary.get("boundaries", {}),
        "budget": {
            "authorization": budget_summary.get("authorizationStatus"),
            "reconciliation": budget_summary.get("reconciliationStatus"),
        },
        "passport": passport_verdict.get("verdict"),
        "federation": federation_verdict.get("verdict"),
        "reputation": reputation_verdict.get("verdict"),
        "provenance_sources": {
            "passport": passport_provenance.get("source"),
            "passport_verdict": passport_cli_verdict.get("source"),
            "presentation": passport_verdict.get("source"),
            "reputation": reputation_verdict.get("source"),
            "evidence_export": federation_export.get("source"),
            "evidence_import": federation_import.get("source"),
            "federated_issue": federation_verdict.get("source"),
        },
        "behavior": behavior_status.get("verdict"),
        "guardrails": {name: artifact.get("denied") for name, artifact in guardrails.items()},
        "rfq": provider_selection.get("status"),
        "subcontractor_lineage_depth": len(subcontractor.get("delegation_chain", [])),
        "runtime_degradation": runtime_degradation.get("status"),
        "observability": observability.get("status"),
        "adversarial": adversarial.get("controls", {}),
    }


def _check_web3(bundle: Path, require_base_sepolia_smoke: bool, errors: list[str]) -> dict[str, Any]:
    index = _load(bundle / "web3/validation-index.json")
    e2e = _load(bundle / "web3/e2e-partner-qualification.json")
    promotion = _load(bundle / "web3/promotion-qualification.json")
    ops = _load(bundle / "web3/ops-incident-audit.json")
    dispatch = _load(bundle / "contracts/web3-settlement-dispatch.json")
    receipt = _load(bundle / "contracts/web3-settlement-receipt.json")
    order = _load(bundle / "contracts/service-order.json")
    quote_request = _load(bundle / "market/quote-request.json")
    rfq_request = _load(bundle / "market/rfq-request.json")
    provider_bids = _load(bundle / "market/provider-bids.json")
    provider_selection = _load(bundle / "market/provider-selection.json")
    quote_response = _load(bundle / "market/quote-response.json")
    fulfillment = _load(bundle / "market/fulfillment-package.json")
    approval = _load(bundle / "approvals/high-risk-release-audit.json")
    payment_proof = _load(bundle / "payments/chio-payment-proof.json")
    payment_satisfaction = _load(bundle / "payments/x402-payment-satisfaction.json")
    rail_selection = _load(bundle / "settlement/rail-selection.json")
    dispute = _load(bundle / "disputes/dispute-summary.json")
    settlement_packet = _load(bundle / "contracts/settlement-packet.json")
    cutover_readiness = _load(bundle / "evidence/cutover-readiness.json")
    reconciliation = _load(bundle / "financial/settlement-reconciliation.json")

    if e2e.get("status") != "pass":
        errors.append("web3 e2e qualification did not pass")
    for check in promotion.get("checks", []):
        if check.get("outcome") != "pass":
            errors.append(f"promotion check failed: {check.get('id')}")
    for assertion in ops.get("assertions", []):
        if assertion.get("result") != "pass":
            errors.append(f"ops assertion failed: {assertion.get('component')}")

    if dispatch.get("schema") != "chio.web3-settlement-dispatch.v1":
        errors.append("dispatch schema mismatch")
    if dispatch.get("settlement_path") != "merkle_proof":
        errors.append("dispatch must use merkle_proof settlement path")
    if dispatch.get("capital_instruction", {}).get("body", {}).get("rail", {}).get("kind") != "web3":
        errors.append("capital instruction rail must be web3")
    if receipt.get("schema") != "chio.web3-settlement-execution-receipt.v1":
        errors.append("receipt schema mismatch")
    if receipt.get("lifecycle_state") != "settled":
        errors.append("receipt lifecycle state must be settled")
    if order.get("order_id") != quote_request.get("order_id"):
        errors.append("quote request does not match order")
    if rfq_request.get("order_id") != order.get("order_id"):
        errors.append("RFQ request does not match order")
    if len(provider_bids.get("bids", [])) != 3:
        errors.append("RFQ must contain three provider bids")
    if provider_selection.get("selected_provider_id") != quote_response.get("provider_id"):
        errors.append("selected provider does not match quote")
    if approval.get("status") != "signed":
        errors.append("approval checkpoint was not signed")
    if payment_proof.get("source_of_truth") != "chio-budget-and-receipts":
        errors.append("x402 payment proof must use Chio as source of truth")
    if payment_satisfaction.get("status") != "satisfied":
        errors.append("x402 payment was not satisfied")
    if rail_selection.get("status") != "pass":
        errors.append("rail selection failed")
    if not rail_selection.get("selected_rail", {}).get("rail_id"):
        errors.append("rail selection missing selected rail")
    if not rail_selection.get("denied_rails"):
        errors.append("rail selection missing denied rail rationale")
    if dispute.get("status") != "resolved":
        errors.append("dispute branch was not resolved")
    if quote_response.get("quote_id") != fulfillment.get("quote_id"):
        errors.append("fulfillment does not match quote")
    if settlement_packet.get("order_id") != order.get("order_id"):
        errors.append("settlement packet does not match order")
    if settlement_packet.get("quote_id") != quote_response.get("quote_id"):
        errors.append("settlement packet does not match quote")
    if settlement_packet.get("fulfillment_id") != fulfillment.get("fulfillment_id"):
        errors.append("settlement packet does not match fulfillment")
    if settlement_packet.get("amount") != dispatch.get("settlement_amount"):
        errors.append("settlement packet amount does not match dispatch")
    if dispatch.get("settlement_packet_id") != settlement_packet.get("packet_id"):
        errors.append("dispatch does not reference settlement packet")
    if cutover_readiness.get("mainnet_blocked") is not True:
        errors.append("cutover readiness must keep mainnet blocked")
    if cutover_readiness.get("local_evidence_present") is not True:
        errors.append("cutover readiness missing local evidence")
    if reconciliation.get("status") != "reconciled":
        errors.append("settlement reconciliation must be reconciled")
    if reconciliation.get("settled_amount") != receipt.get("observed_execution", {}).get("amount"):
        errors.append("reconciliation settled amount does not match receipt")
    expected_amount = {
        "units": quote_response.get("price_minor_units"),
        "currency": quote_response.get("currency"),
    }
    if dispatch.get("settlement_amount") != expected_amount:
        errors.append("dispatch amount does not match quote")

    smoke_index = index.get("base_sepolia_live_smoke", {})
    included = bool(smoke_index.get("included"))
    if require_base_sepolia_smoke and not included:
        errors.append("Base Sepolia smoke report was required but not attached")
    if included:
        smoke = _load(bundle / "web3/base-sepolia-smoke.json")
        deployment = _load(bundle / "web3/base-sepolia-deployment.json")
        tx_ids = set(smoke_index.get("transaction_ids", []))
        missing = sorted(REQUIRED_BASE_SEPOLIA_TX_IDS - tx_ids)
        if smoke.get("status") != "pass":
            errors.append("Base Sepolia smoke did not pass")
        if smoke.get("chain_id") != "eip155:84532":
            errors.append("Base Sepolia smoke chain id mismatch")
        if missing:
            errors.append(f"Base Sepolia smoke missing transaction ids: {', '.join(missing)}")
        for check in smoke.get("checks", []):
            if check.get("outcome") != "pass":
                errors.append(f"Base Sepolia smoke check failed: {check.get('id')}")
        contracts = deployment.get("deployed_contract_addresses", {})
        for contract_id in [
            "chio.identity-registry",
            "chio.root-registry",
            "chio.escrow",
            "chio.bond-vault",
            "chio.price-resolver",
        ]:
            if not contracts.get(contract_id):
                errors.append(f"deployment missing {contract_id}")

    return {
        "e2e_status": e2e.get("status"),
        "promotion_checks": len(promotion.get("checks", [])),
        "ops_assertions": len(ops.get("assertions", [])),
        "settlement_packet_status": settlement_packet.get("status"),
        "rfq_selection_status": provider_selection.get("status"),
        "approval_status": approval.get("status"),
        "x402_payment_status": payment_satisfaction.get("status"),
        "rail_selection_status": rail_selection.get("status"),
        "dispute_status": dispute.get("status"),
        "base_sepolia_live_smoke_included": included,
        "base_sepolia_tx_count": smoke_index.get("tx_count", 0),
    }


def verify_bundle(
    bundle_path: str | Path,
    *,
    require_base_sepolia_smoke: bool = False,
) -> dict[str, Any]:
    bundle = Path(bundle_path)
    errors: list[str] = []
    for rel in REQUIRED:
        if not (bundle / rel).exists():
            errors.append(f"missing: {rel}")
    if errors:
        return {"bundle": str(bundle), "ok": False, "errors": errors}

    manifest = _check_manifest(bundle, errors)
    capabilities = _check_capabilities(bundle, errors)
    web3 = _check_web3(bundle, require_base_sepolia_smoke, errors)
    chio = _check_chio(bundle, errors)
    summary = _load(bundle / "summary.json")
    if summary.get("chio_mediated") is not True:
        errors.append("summary must report Chio mediation")
    if summary.get("mediation_status") != "pass":
        errors.append("summary mediation status failed")
    if summary.get("settlement_status") != "settled":
        errors.append("summary settlement status must be settled")
    if summary.get("reconciliation_status") != "reconciled":
        errors.append("summary reconciliation status must be reconciled")
    if summary.get("budget_reconciliation") != "reconciled":
        errors.append("summary budget reconciliation must be reconciled")
    expected_summary = {
        "rfq_selection_status": "pass",
        "subcontract_lineage_depth": 2,
        "dispute_status": "resolved",
        "approval_status": "signed",
        "x402_payment_status": "satisfied",
        "rail_selection_status": "pass",
        "runtime_degradation_status": "quarantined_then_reattested",
        "observability_status": "correlated",
        "historical_reputation_status": "pass",
    }
    for key, expected in expected_summary.items():
        if summary.get(key) != expected:
            errors.append(f"summary {key} expected {expected!r}, got {summary.get(key)!r}")
    adversarial_status = summary.get("adversarial_denial_status", {})
    for control in [
        "prompt_injection",
        "invoice_tampering",
        "quote_replay",
        "expired_capability",
        "unauthorized_settlement_route",
        "forged_passport",
    ]:
        if adversarial_status.get(control) != "denied":
            errors.append(f"summary adversarial control did not deny: {control}")

    return {
        "bundle": str(bundle),
        "ok": not errors,
        "manifest": manifest,
        "capabilities": capabilities,
        "web3": web3,
        "chio": chio,
        "errors": errors,
    }
