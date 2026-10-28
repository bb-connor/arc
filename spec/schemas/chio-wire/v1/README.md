# Chio Wire Schemas v1

These files are the machine-readable schema contract for the shipped native Chio
message families defined in [WIRE_PROTOCOL.md](../../../WIRE_PROTOCOL.md).

The JSON Schema documents in this directory are the source of truth for the
Chio v1 wire contract. Any SDK, codegen pipeline, or conformance harness that
needs to validate Chio payloads should resolve types from these files first
and treat hand-typed bindings as derived artifacts.

Directory layout:

- `agent/`
  - `tool_call_request.schema.json`
  - `list_capabilities.schema.json`
  - `heartbeat.schema.json`
- `kernel/`
  - `tool_call_chunk.schema.json`
  - `tool_call_response.schema.json`
  - `execution_nonce.schema.json`
  - `capability_list.schema.json`
  - `capability_revoked.schema.json`
  - `heartbeat.schema.json`
- `result/`
  - `ok.schema.json`
  - `stream_complete.schema.json`
  - `pending_approval.schema.json`
  - `cancelled.schema.json`
  - `incomplete.schema.json`
  - `err.schema.json`
- `error/`
  - `capability_denied.schema.json`
  - `capability_expired.schema.json`
  - `capability_revoked.schema.json`
  - `policy_denied.schema.json`
  - `tool_server_error.schema.json`
  - `internal_error.schema.json`
- `capability/` - capability tokens, grants, revocation envelopes, and the
  `chio.capability-presentation.v1` envelope (`presentation.schema.json`).
- `jsonrpc/` - JSON-RPC framing used by the hosted MCP HTTP edge.
- `provenance/` - provenance and attestation records emitted by the kernel.
- `receipt/` - signed receipts produced after tool calls complete, the
  `chio.receipt-disclosure.v1` opening (`disclosure.schema.json`), and the
  signed `chio.settlement-closure.v1` (`settlement-closure.schema.json`).
- `root_authority/` - anchored-root artifacts: `root_anchor` and the shared
  definitions (`root-anchor.schema.json`), the delegation context, the signed
  root policy, the enterprise provider identity projection, the signed
  identity-provider key snapshot, the verifier trust file, and the signed
  caller revocation request. Valid and invalid instances live under
  `root_authority/examples/`; `scripts/check-root-authority-schema-examples.py`
  checks them, each invalid instance against the error path and keyword in
  `examples/invalid-expectations.json`.

Source-of-truth pointers:

- The Rust types backing these schemas live in `crates/core/chio-core-types`. When
  Rust types and these schemas disagree, fix the schema or the type so they
  match again before shipping.
- Cross-language conformance vectors live under `tests/bindings/vectors/`
  (canonical JSON, capability, hashing, manifest, receipt, security, signing).
  SDKs in other languages must round-trip those vectors through their
  generated bindings.

<!-- BEGIN generated signed-artifact schemas -->

Signed-artifact bodies generated from recorded examples by
`scripts/gen-signed-artifact-schemas.py`:

- `chio.active-response-artifact-authority-attestation.v1`: `kernel/active-response-artifact-authority-attestation.schema.json`
- `chio.active-response-policy-authority-request.v1`: `kernel/active-response-policy-authority-request.schema.json`
- `chio.active-response-policy-authority-response.v1`: `kernel/active-response-policy-authority-response.schema.json`
- `chio.active-response-submission.v1`: `kernel/active-response-submission.schema.json`
- `chio.ag-ui-receipt.v1`: `receipt/ag-ui-receipt.schema.json`
- `chio.agent-passport-presentation-response.v1`: `trust/agent-passport-presentation-response.schema.json`
- `chio.authority-lifecycle.v1`: `kernel/authority-lifecycle.schema.json`
- `chio.authority-snapshot.v1`: `kernel/authority-snapshot.schema.json`
- `chio.autonomous-comparison-report.v1`: `economy/autonomous-comparison-report.schema.json`
- `chio.autonomous-drift-report.v1`: `economy/autonomous-drift-report.schema.json`
- `chio.autonomous-execution-decision.v1`: `economy/autonomous-execution-decision.schema.json`
- `chio.autonomous-pricing-authority-envelope.v1`: `economy/autonomous-pricing-authority-envelope.schema.json`
- `chio.autonomous-pricing-decision.v1`: `economy/autonomous-pricing-decision.schema.json`
- `chio.autonomous-pricing-input.v1`: `economy/autonomous-pricing-input.schema.json`
- `chio.autonomous-rollback-plan.v1`: `economy/autonomous-rollback-plan.schema.json`
- `chio.behavioral-feed.v1`: `kernel/behavioral-feed.schema.json`
- `chio.budget-snapshot-anchor-commitment.v1`: `kernel/budget-snapshot-anchor-commitment.schema.json`
- `chio.call_chain_continuation.v1`: `capability/call-chain-continuation.schema.json`
- `chio.capital-pool-optimization.v1`: `economy/capital-pool-optimization.schema.json`
- `chio.capital-pool-simulation-report.v1`: `economy/capital-pool-simulation-report.schema.json`
- `chio.certify.check.v1`: `certify/check.schema.json`
- `chio.checkpoint_statement.v1`: `kernel/checkpoint-statement.schema.json`
- `chio.child-request-receipt.v1`: `receipt/child-request-receipt.schema.json`
- `chio.compliance.certificate.v1`: `compliance/certificate.schema.json`
- `chio.credit.bond.v1`: `credit/bond.schema.json`
- `chio.credit.capital-allocation.v1`: `credit/capital-allocation.schema.json`
- `chio.credit.capital-authority-step-proof.v1`: `credit/capital-authority-step-proof.schema.json`
- `chio.credit.capital-book.v1`: `credit/capital-book.schema.json`
- `chio.credit.capital-instruction.v1`: `credit/capital-instruction.schema.json`
- `chio.credit.exposure-ledger.v1`: `credit/exposure-ledger.schema.json`
- `chio.credit.facility.v1`: `credit/facility.schema.json`
- `chio.credit.iou-envelope.v1`: `credit/iou-envelope.schema.json`
- `chio.credit.loss-lifecycle.v1`: `credit/loss-lifecycle.schema.json`
- `chio.credit.provider-risk-package.v1`: `credit/provider-risk-package.schema.json`
- `chio.credit.scorecard.v1`: `credit/scorecard.schema.json`
- `chio.cross-issuer-migration.v1`: `federation/cross-issuer-migration.schema.json`
- `chio.delegation-link.v1`: `capability/delegation-link.schema.json`
- `chio.enterprise-migration-transition.v1`: `federation/enterprise-migration-transition.schema.json`
- `chio.evidence_export_commitment.v1`: `kernel/evidence-export-commitment.schema.json`
- `chio.execution_nonce.v1`: `kernel/execution-nonce-body.schema.json`
- `chio.federated-delegation-policy.v1`: `federation/federated-delegation-policy.schema.json`
- `chio.federation-activation-exchange.v1`: `federation/federation-activation-exchange.schema.json`
- `chio.federation-kernel-handshake.v1`: `federation/federation-kernel-handshake.schema.json`
- `chio.federation-open-admission-policy.v1`: `federation/federation-open-admission-policy.schema.json`
- `chio.federation-policy.v1`: `federation/federation-policy.schema.json`
- `chio.federation-qualification-matrix.v1`: `federation/federation-qualification-matrix.schema.json`
- `chio.federation-quorum-report.v1`: `federation/federation-quorum-report.schema.json`
- `chio.federation-reputation-clearing.v1`: `federation/federation-reputation-clearing.schema.json`
- `chio.federation.transport.iroh.peer-directory-bundle.v1`: `federation/transport-iroh-peer-directory-bundle.schema.json`
- `chio.financial-agent-passport-presentation-response.v1`: `trust/financial-agent-passport-presentation-response.schema.json`
- `chio.financial.cross-issuer-entry-activation-decision.v1`: `financial/cross-issuer-entry-activation-decision.schema.json`
- `chio.financial.cross-issuer-migration.v1`: `financial/cross-issuer-migration.schema.json`
- `chio.financial.cross-issuer-trust-pack.v1`: `financial/cross-issuer-trust-pack.schema.json`
- `chio.financial.cross-issuer.lifecycle-checkpoint-pin.v1`: `financial/cross-issuer-lifecycle-checkpoint-pin.schema.json`
- `chio.financial.cross-issuer.lifecycle-checkpoint.v1`: `financial/cross-issuer-lifecycle-checkpoint.schema.json`
- `chio.financial.cross-issuer.lifecycle-generation-pin.v1`: `financial/cross-issuer-lifecycle-generation-pin.schema.json`
- `chio.financial.cross-issuer.lifecycle-result.v1`: `financial/cross-issuer-lifecycle-result.schema.json`
- `chio.finding-pool.store-identity-proof.v1`: `finding/store-identity-proof.schema.json`
- `chio.finding-status-operator-authorization.v1`: `finding/status-operator-authorization.schema.json`
- `chio.finding.anchor-checkpoint-publication.v1`: `finding/anchor-checkpoint-publication.schema.json`
- `chio.finding.audit-seed-witness.v1`: `finding/audit-seed-witness.schema.json`
- `chio.finding.bond-store-snapshot.v1`: `finding/bond-store-snapshot.schema.json`
- `chio.finding.current-listing-assertion.v1`: `finding/current-listing-assertion.schema.json`
- `chio.finding.hosted-api-key-lifecycle.v1`: `finding/hosted-api-key-lifecycle.schema.json`
- `chio.finding.hosted-archive-manifest.v1`: `finding/hosted-archive-manifest.schema.json`
- `chio.finding.hosted-authority-transition.v1`: `finding/hosted-authority-transition.schema.json`
- `chio.finding.hosted-canary-observation.v1`: `finding/hosted-canary-observation.schema.json`
- `chio.finding.hosted-gc-receipt.v1`: `finding/hosted-gc-receipt.schema.json`
- `chio.finding.hosted-journal-checkpoint.v1`: `finding/hosted-journal-checkpoint.schema.json`
- `chio.finding.hosted-legal-hold.v1`: `finding/hosted-legal-hold.schema.json`
- `chio.finding.hosted-principal-lifecycle.v1`: `finding/hosted-principal-lifecycle.schema.json`
- `chio.finding.hosted-principal-replication-event.v1`: `finding/hosted-principal-replication-event.schema.json`
- `chio.finding.hosted-quota-alert.v1`: `finding/hosted-quota-alert.schema.json`
- `chio.finding.hosted-replication-check.v1`: `finding/hosted-replication-check.schema.json`
- `chio.finding.hosted-replication-event.v1`: `finding/hosted-replication-event.schema.json`
- `chio.finding.hosted-restore-verification.v1`: `finding/hosted-restore-verification.schema.json`
- `chio.finding.hosted-sqlite-import-batch.v1`: `finding/hosted-sqlite-import-batch.schema.json`
- `chio.finding.hosted.aggregate-checkpoint.v1`: `finding/hosted-aggregate-checkpoint.schema.json`
- `chio.finding.operator-purchase-job.v1`: `finding/operator-purchase-job.schema.json`
- `chio.finding.pool-debit-authorization.v1`: `finding/pool-debit-authorization.schema.json`
- `chio.finding.status-intent-submission.v1`: `finding/status-intent-submission.schema.json`
- `chio.finding.voluntary-retraction-receipt.v1`: `finding/voluntary-retraction-receipt.schema.json`
- `chio.finding.worker-attested-result.v1`: `finding/worker-attested-result.schema.json`
- `chio.finding.worker-capability.v1`: `finding/worker-capability.schema.json`
- `chio.frost.dkg-package.v1`: `frost/dkg-package.schema.json`
- `chio.governed-approval-token.v1`: `capability/governed-approval-token-body.schema.json`
- `chio.governed-upstream-call-chain-proof.v1`: `capability/governed-upstream-call-chain-proof.schema.json`
- `chio.http-receipt.v1`: `receipt/http-receipt.schema.json`
- `chio.iroh.revocation-signer-endorsement.v1`: `iroh/revocation-signer-endorsement.schema.json`
- `chio.iroh.transport-endorsement.v1`: `iroh/transport-endorsement.schema.json`
- `chio.key-binding-certificate.v1`: `trust/key-binding-certificate.schema.json`
- `chio.key-log.witness-statement.v1`: `security/witness-statement.schema.json`
- `chio.lineage.frontier-signature.v1`: `lineage/frontier-signature.schema.json`
- `chio.market.auto-bind.v1`: `market/auto-bind.schema.json`
- `chio.market.bound-coverage.v1`: `market/bound-coverage.schema.json`
- `chio.market.claim-adjudication.v1`: `market/claim-adjudication.schema.json`
- `chio.market.claim-dispute.v1`: `market/claim-dispute.schema.json`
- `chio.market.claim-package.v1`: `market/claim-package.schema.json`
- `chio.market.claim-payout-instruction.v1`: `market/claim-payout-instruction.schema.json`
- `chio.market.claim-payout-receipt.v1`: `market/claim-payout-receipt.schema.json`
- `chio.market.claim-response.v1`: `market/claim-response.schema.json`
- `chio.market.claim-settlement-instruction.v1`: `market/claim-settlement-instruction.schema.json`
- `chio.market.claim-settlement-receipt.v1`: `market/claim-settlement-receipt.schema.json`
- `chio.market.placement.v1`: `market/placement.schema.json`
- `chio.market.pricing-authority.v1`: `market/pricing-authority.schema.json`
- `chio.market.provider.v1`: `market/provider.schema.json`
- `chio.market.quote-request.v1`: `market/quote-request.schema.json`
- `chio.market.quote-response.v1`: `market/quote-response.schema.json`
- `chio.marketplace.accepted-bid.v1`: `marketplace/accepted-bid.schema.json`
- `chio.marketplace.ask-response.v1`: `marketplace/ask-response.schema.json`
- `chio.marketplace.bid-request.v1`: `marketplace/bid-request.schema.json`
- `chio.marketplace.listing-pricing-hint.v1`: `marketplace/listing-pricing-hint.schema.json`
- `chio.marketplace.reservation-receipt.v1`: `marketplace/reservation-receipt.schema.json`
- `chio.mcp.operator-approval.v1`: `mcp/operator-approval.schema.json`
- `chio.mcp.session-credential-call.v1`: `mcp/session-credential-call.schema.json`
- `chio.mcp.session-credential.v1`: `mcp/session-credential.schema.json`
- `chio.operation_execution_nonce.v1`: `kernel/operation-execution-nonce-body.schema.json`
- `chio.parametric.contest.v1`: `parametric/contest.schema.json`
- `chio.parametric.evidence-source-checkpoint.v1`: `parametric/evidence-source-checkpoint.schema.json`
- `chio.parametric.payout-intent.v1`: `parametric/payout-intent.schema.json`
- `chio.passkey-capability.v1`: `trust/passkey-capability.schema.json`
- `chio.passport-verifier-policy.v1`: `trust/passport-verifier-policy.schema.json`
- `chio.policy.activation-receipt-signature.v1`: `policy/activation-receipt-signature.schema.json`
- `chio.portable-agent-passport.v1`: `trust/portable-agent-passport.schema.json`
- `chio.portable-negative-event.v1`: `trust/portable-negative-event.schema.json`
- `chio.portable-reputation-summary.v1`: `trust/portable-reputation-summary.schema.json`
- `chio.process.container-launch.v1`: `process/container-launch.schema.json`
- `chio.process.swarm-profile.v1`: `process/swarm-profile.schema.json`
- `chio.provenance-stamp.v1`: `provenance/provenance-stamp.schema.json`
- `chio.public-discovery-transparency.v1`: `trust/public-discovery-transparency.schema.json`
- `chio.public-issuer-discovery.v1`: `trust/public-issuer-discovery.schema.json`
- `chio.public-verifier-discovery.v1`: `trust/public-verifier-discovery.schema.json`
- `chio.registry.governance-case.v1`: `registry/governance-case.schema.json`
- `chio.registry.governance-charter.v1`: `registry/governance-charter.schema.json`
- `chio.registry.listing.v1`: `registry/listing.schema.json`
- `chio.registry.market-fee-schedule.v1`: `registry/market-fee-schedule.schema.json`
- `chio.registry.namespace.v1`: `registry/namespace.schema.json`
- `chio.registry.trust-activation.v1`: `registry/trust-activation.schema.json`
- `chio.regulatory.receipt-export.v1`: `regulatory/receipt-export.schema.json`
- `chio.release-qualification-manifest.v1`: `release/release-qualification-manifest.schema.json`
- `chio.reputation-credential.v1`: `trust/reputation-credential.schema.json`
- `chio.request_lineage_record.v1`: `kernel/request-lineage-record.schema.json`
- `chio.runtime-attestation-evidence.v1`: `runtime-attestation/evidence.schema.json`
- `chio.runtime-attestation.appraisal-report.v1`: `runtime-attestation/appraisal-report.schema.json`
- `chio.runtime-attestation.appraisal-result.v1`: `runtime-attestation/appraisal-result.schema.json`
- `chio.runtime-attestation.reference-values.v1`: `runtime-attestation/reference-values.schema.json`
- `chio.runtime-attestation.trust-bundle.v1`: `runtime-attestation/trust-bundle.schema.json`
- `chio.runtime-attestation.verifier-descriptor.v1`: `runtime-attestation/verifier-descriptor.schema.json`
- `chio.runtime.attack-simulation-report-signature.v1`: `runtime/attack-simulation-report-signature.schema.json`
- `chio.runtime.chaos-run-report-signature.v1`: `runtime/chaos-run-report-signature.schema.json`
- `chio.runtime.execution-lease-signature.v1`: `runtime/execution-lease-signature.schema.json`
- `chio.runtime.revocation-freshness-proof-signature.v1`: `runtime/revocation-freshness-proof-signature.schema.json`
- `chio.runtime.sandbox-attestation-signature.v1`: `runtime/sandbox-attestation-signature.schema.json`
- `chio.runtime.terminal-receipt-signature.v1`: `runtime/terminal-receipt-signature.schema.json`
- `chio.runtime.tool-server-ack-signature.v1`: `runtime/tool-server-ack-signature.schema.json`
- `chio.runtime.trusted-time-proof-signature.v1`: `runtime/trusted-time-proof-signature.schema.json`
- `chio.session-compliance-certificate.v1`: `kernel/session-compliance-certificate.schema.json`
- `chio.session_anchor.v1`: `kernel/session-anchor.schema.json`
- `chio.signed-admission-terminal-projection.v1`: `kernel/signed-admission-terminal-projection.schema.json`
- `chio.signed-watermark-envelope.v1`: `security/signed-watermark-envelope.schema.json`
- `chio.signer-readiness-probe.v1`: `kernel/signer-readiness-probe.schema.json`
- `chio.stop-operator-config-approval.v1`: `kernel/stop-operator-config-approval.schema.json`
- `chio.stop-operator-config.v1`: `kernel/stop-operator-config.schema.json`
- `chio.swarm.delegation-witness-hop-signature.v1`: `swarm/delegation-witness-hop-signature.schema.json`
- `chio.swarm.route-plan-receipt-signature.v1`: `swarm/route-plan-receipt-signature.schema.json`
- `chio.tee-bless-audit.v1`: `runtime/tee-bless-audit.schema.json`
- `chio.tee-capture-frame.v1`: `runtime/tee-capture-frame.schema.json`
- `chio.trace-observation.v1`: `provenance/trace-observation.schema.json`
- `chio.underwriting.decision.v1`: `underwriting/decision.schema.json`
- `chio.underwriting.policy-input.v1`: `underwriting/policy-input.schema.json`
- `chio.wasm-module.v1`: `runtime/wasm-module.schema.json`
- `chio.work-dispatch-permit.v1`: `work/work-dispatch-permit.schema.json`
- `chio.work-offer.v1`: `work/work-offer.schema.json`
- `chio.work-selection.v1`: `work/work-selection.schema.json`
- `chio.work-subdivision.v1`: `work/work-subdivision.schema.json`
- `chio.workflow-receipt.v1`: `workflow/workflow-receipt.schema.json`

<!-- END generated signed-artifact schemas -->
