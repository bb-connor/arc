# Wire-schema identifiers declared in more than one file

Every identifier value below is declared as a `&str` constant in two or more
production files. The strings agree today; the failure mode is the day one is
bumped and the other is not, which compiles cleanly and is caught by nothing
unless a test pins the literal. One declaration per value, imported everywhere
else, is the target shape. Measured by `scripts/check-wire-schemas.py` on
2026-09-26; `spec/wire-schemas.lock` records the same files without line
numbers and is what the gate enforces. This list is for the owners of the
declaring crates and is not itself gated.

200 values are declared in more than one file, 199 of them across
crate boundaries; 57 of the 200 reuse one constant name, the rest carry
different names for the same bytes.

## `chio.receipt.v1` (6 declarations, 5 crates)

- `crates/core/chio-core-types/src/receipt/body.rs:39` `CHIO_RECEIPT_SCHEMA`
- `crates/platform/chio-enterprise-export/src/artifacts.rs:22` `CHIO_RECEIPT_SCHEMA`
- `crates/platform/chio-trust-market-context/src/evidence.rs:9` `CHIO_RECEIPT_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/collect.rs:14` `CHIO_RECEIPT_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/risk.rs:17` `CHIO_RECEIPT_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:839` `CHIO_RECEIPT_SCHEMA`

## `chio.commerce.provider-selection-report.v1` (5 declarations, 5 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:212` `CHIO_COMMERCE_PROVIDER_SELECTION_REPORT_V1_SCHEMA`
- `crates/platform/chio-enterprise-export/src/artifacts.rs:23` `COMMERCE_PROVIDER_SELECTION_REPORT_SCHEMA`
- `crates/platform/chio-trust-market-context/src/evidence.rs:10` `COMMERCE_PROVIDER_SELECTION_REPORT_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/risk.rs:15` `COMMERCE_PROVIDER_SELECTION_REPORT_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:837` `COMMERCE_PROVIDER_SELECTION_REPORT_SCHEMA`

## `chio.risk.adjudication-jurisdiction-receipt.v1` (5 declarations, 5 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:255` `CHIO_RISK_ADJUDICATION_JURISDICTION_RECEIPT_V1_SCHEMA`
- `crates/platform/chio-enterprise-export/src/artifacts.rs:30` `RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA`
- `crates/platform/chio-trust-market-context/src/evidence.rs:12` `RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/risk.rs:12` `RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:834` `RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA`

## `chio.risk.guarantee-decision.v1` (5 declarations, 5 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:254` `CHIO_RISK_GUARANTEE_DECISION_V1_SCHEMA`
- `crates/platform/chio-enterprise-export/src/artifacts.rs:32` `RISK_GUARANTEE_DECISION_SCHEMA`
- `crates/platform/chio-trust-market-context/src/evidence.rs:15` `RISK_GUARANTEE_DECISION_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/risk.rs:14` `RISK_GUARANTEE_DECISION_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:836` `RISK_GUARANTEE_DECISION_SCHEMA`

## `chio.web3-settlement-execution-receipt.v2` (5 declarations, 5 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:294` `CHIO_WEB3_SETTLEMENT_EXECUTION_RECEIPT_V2_SCHEMA`
- `crates/economy/chio-web3/src/settlement.rs:29` `CHIO_WEB3_SETTLEMENT_RECEIPT_V2_SCHEMA`
- `crates/platform/chio-enterprise-export/src/artifacts.rs:33` `WEB3_SETTLEMENT_EXECUTION_RECEIPT_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/risk.rs:18` `WEB3_SETTLEMENT_EXECUTION_RECEIPT_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:840` `WEB3_SETTLEMENT_EXECUTION_RECEIPT_SCHEMA`

## `chio.web3-settlement-proof-bundle.v1` (5 declarations, 5 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:296` `CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_V1_SCHEMA`
- `crates/economy/chio-web3/src/settlement_proof.rs:19` `CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA`
- `crates/platform/chio-enterprise-export/src/artifacts.rs:34` `WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/risk.rs:19` `WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:841` `WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA`

## `chio.enterprise.approval-case.v1` (4 declarations, 4 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:265` `CHIO_ENTERPRISE_APPROVAL_CASE_V1_SCHEMA`
- `crates/platform/chio-enterprise-export/src/artifacts.rs:25` `ENTERPRISE_APPROVAL_CASE_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/risk.rs:7` `ENTERPRISE_APPROVAL_CASE_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:829` `ENTERPRISE_APPROVAL_CASE_SCHEMA`

## `chio.enterprise.control-evidence-map.v1` (4 declarations, 4 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:266` `CHIO_ENTERPRISE_CONTROL_EVIDENCE_MAP_V1_SCHEMA`
- `crates/platform/chio-enterprise-export/src/artifacts.rs:26` `ENTERPRISE_CONTROL_EVIDENCE_MAP_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/risk.rs:8` `ENTERPRISE_CONTROL_EVIDENCE_MAP_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:830` `ENTERPRISE_CONTROL_EVIDENCE_MAP_SCHEMA`

## `chio.enterprise.data-governance-report.v1` (4 declarations, 4 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:259` `CHIO_ENTERPRISE_DATA_GOVERNANCE_REPORT_V1_SCHEMA`
- `crates/platform/chio-enterprise-export/src/artifacts.rs:27` `ENTERPRISE_DATA_GOVERNANCE_REPORT_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/risk.rs:9` `ENTERPRISE_DATA_GOVERNANCE_REPORT_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:831` `ENTERPRISE_DATA_GOVERNANCE_REPORT_SCHEMA`

## `chio.enterprise.evidence-export-bundle.v1` (4 declarations, 4 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:261` `CHIO_ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_V1_SCHEMA`
- `crates/platform/chio-enterprise-export/src/artifacts.rs:28` `ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/risk.rs:10` `ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:832` `ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA`

## `chio.enterprise.telemetry-projection.v1` (4 declarations, 4 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:263` `CHIO_ENTERPRISE_TELEMETRY_PROJECTION_V1_SCHEMA`
- `crates/platform/chio-enterprise-export/src/artifacts.rs:29` `ENTERPRISE_TELEMETRY_PROJECTION_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/risk.rs:11` `ENTERPRISE_TELEMETRY_PROJECTION_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:833` `ENTERPRISE_TELEMETRY_PROJECTION_SCHEMA`

## `chio.proof-room.fixture-root-catalog.v1` (4 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:277` `CHIO_PROOF_ROOM_FIXTURE_ROOT_CATALOG_V1_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/doctor.rs:6` `PROOF_FIXTURE_ROOT_CATALOG_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:32` `PROOF_FIXTURE_CATALOG_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:112` `PROOF_FIXTURE_CATALOG_SCHEMA`

## `chio.risk.comptroller-report.v1` (4 declarations, 4 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:251` `CHIO_RISK_COMPTROLLER_REPORT_V1_SCHEMA`
- `crates/platform/chio-commerce-order/src/lib.rs:47` `RISK_COMPTROLLER_REPORT_SCHEMA_ID`
- `crates/platform/chio-control-plane/src/transaction_passport_risk.rs:11` `RISK_COMPTROLLER_REPORT_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/risk.rs:6` `RISK_COMPTROLLER_REPORT_SCHEMA`

## `chio.runtime.terminal-receipt.v1` (4 declarations, 4 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:289` `CHIO_RUNTIME_TERMINAL_RECEIPT_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:13` `RUNTIME_TERMINAL_RECEIPT_SCHEMA_ID`
- `crates/products/chio-cli/src/cli/dispatch/proof/collect.rs:15` `RUNTIME_TERMINAL_RECEIPT_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:56` `RUNTIME_TERMINAL_RECEIPT_SCHEMA`

## `chio.anchor-proof-bundle.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:31` `CHIO_ANCHOR_PROOF_BUNDLE_V1_SCHEMA`
- `crates/economy/chio-anchor/src/bundle.rs:12` `CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA_V1`
- `crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs:58` `CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA`

## `chio.checkpoint_statement.v1` (3 declarations, 3 crates)

- `crates/economy/chio-web3/src/anchors.rs:18` `CHIO_CHECKPOINT_STATEMENT_SCHEMA_V1`
- `crates/kernel/chio-kernel/src/checkpoint.rs:39` `CHECKPOINT_SCHEMA_V1`
- `crates/platform/chio-transaction-passport/src/minimal.rs:798` `CHECKPOINT_STATEMENT_SCHEMA_V1_ID`

## `chio.checkpoint_statement.v2` (3 declarations, 3 crates)

- `crates/economy/chio-web3/src/anchors.rs:19` `CHIO_CHECKPOINT_STATEMENT_SCHEMA_V2`
- `crates/kernel/chio-kernel/src/checkpoint.rs:41` `CHECKPOINT_SCHEMA_V2`
- `crates/platform/chio-transaction-passport/src/minimal.rs:799` `CHECKPOINT_STATEMENT_SCHEMA_V2_ID`

## `chio.proof-room.bundle.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:274` `CHIO_PROOF_ROOM_BUNDLE_V1_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/collect.rs:4` `PROOF_ROOM_BUNDLE_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:43` `PROOF_ROOM_BUNDLE_SCHEMA`

## `chio.proof-room.receipt-evidence.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:279` `CHIO_PROOF_ROOM_RECEIPT_EVIDENCE_V1_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/doctor.rs:7` `PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:53` `PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA`

## `chio.proof-room.verifier-report.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:275` `CHIO_PROOF_ROOM_VERIFIER_REPORT_V1_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/collect.rs:5` `PROOF_ROOM_VERIFIER_REPORT_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:44` `PROOF_ROOM_VERIFIER_REPORT_SCHEMA`

## `chio.proof.docker-quickstart-evidence.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:280` `CHIO_PROOF_DOCKER_QUICKSTART_EVIDENCE_V1_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/doctor.rs:8` `DOCKER_QUICKSTART_EVIDENCE_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:45` `PROOF_ROOM_DOCKER_QUICKSTART_EVIDENCE_SCHEMA`

## `chio.proof.first-run.trust-roots.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:287` `CHIO_PROOF_FIRST_RUN_TRUST_ROOTS_V1_SCHEMA`
- `crates/products/chio-cli/src/cli/dispatch/proof/collect.rs:11` `PROOF_ROOM_TRUST_ROOTS_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:51` `PROOF_ROOM_FIRST_RUN_TRUST_ROOTS_SCHEMA`

## `chio.request.digest.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:195` `CHIO_REQUEST_DIGEST_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:8` `REQUEST_DIGEST_SCHEMA_ID`
- `crates/products/chio-proof-room/src/lib.rs:54` `TRANSACTION_REQUEST_DIGEST_SCHEMA`

## `chio.runtime-attestation.aws-nitro-attestation.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/runtime_attestation.rs:13` `AWS_NITRO_ATTESTATION_SCHEMA`
- `crates/economy/chio-appraisal/src/types.rs:17` `AWS_NITRO_ATTESTATION_SCHEMA`
- `crates/platform/chio-control-plane/src/attestation.rs:39` `AWS_NITRO_ATTESTATION_SCHEMA`

## `chio.runtime-attestation.azure-maa.jwt.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/runtime_attestation.rs:12` `AZURE_MAA_ATTESTATION_SCHEMA`
- `crates/economy/chio-appraisal/src/types.rs:16` `AZURE_MAA_ATTESTATION_SCHEMA`
- `crates/platform/chio-control-plane/src/attestation.rs:37` `AZURE_MAA_ATTESTATION_SCHEMA`

## `chio.runtime.evidence-manifest.v1` (3 declarations, 3 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:7` `CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA`
- `crates/kernel/chio-runtime-proof-parity/src/lib.rs:6` `CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:97` `CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA`

## `chio.runtime.proof-parity-report.v1` (3 declarations, 3 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:12` `CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA`
- `crates/kernel/chio-runtime-proof-parity/src/lib.rs:7` `CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:102` `CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA`

## `chio.runtime.proof-regeneration-input.v1` (3 declarations, 3 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:8` `CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA`
- `crates/kernel/chio-runtime-proof-parity/src/lib.rs:8` `CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:98` `CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA`

## `chio.runtime.proof-regeneration-report.v1` (3 declarations, 3 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:10` `CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA`
- `crates/kernel/chio-runtime-proof-parity/src/lib.rs:10` `CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:100` `CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA`

## `chio.runtime.trust-floor-state.v1` (3 declarations, 3 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:19` `CHIO_RUNTIME_TRUST_FLOOR_STATE_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:109` `CHIO_RUNTIME_TRUST_FLOOR_STATE_SCHEMA`
- `crates/trust/chio-pheromone/src/lib.rs:44` `RUNTIME_TRUST_FLOOR_STATE_SCHEMA`

## `chio.runtime.trusted-time-proof.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:244` `CHIO_RUNTIME_TRUSTED_TIME_PROOF_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:12` `RUNTIME_TRUSTED_TIME_PROOF_SCHEMA_ID`
- `crates/products/chio-proof-room/src/lib.rs:57` `RUNTIME_TRUSTED_TIME_PROOF_SCHEMA`

## `chio.runtime.workflow-run-report.v1` (3 declarations, 3 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:5` `CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA`
- `crates/kernel/chio-runtime-proof-parity/src/lib.rs:12` `CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:95` `CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA`

## `chio.swarm.budget-pool.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:308` `CHIO_SWARM_BUDGET_POOL_V1_SCHEMA`
- `crates/kernel/chio-swarm-authority/src/types.rs:10` `CHIO_SWARM_BUDGET_POOL_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:22` `SWARM_BUDGET_POOL_SCHEMA_ID`

## `chio.swarm.join-receipt.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:304` `CHIO_SWARM_JOIN_RECEIPT_V1_SCHEMA`
- `crates/kernel/chio-swarm-authority/src/types.rs:8` `CHIO_SWARM_JOIN_RECEIPT_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:21` `SWARM_JOIN_RECEIPT_SCHEMA_ID`

## `chio.swarm.route-plan-receipt.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:305` `CHIO_SWARM_ROUTE_PLAN_RECEIPT_V1_SCHEMA`
- `crates/kernel/chio-swarm-authority/src/types.rs:9` `CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:23` `SWARM_ROUTE_PLAN_RECEIPT_SCHEMA_ID`

## `chio.swarm.task-graph.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:300` `CHIO_SWARM_TASK_GRAPH_V1_SCHEMA`
- `crates/kernel/chio-swarm-authority/src/types.rs:4` `CHIO_SWARM_TASK_GRAPH_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:20` `SWARM_TASK_GRAPH_SCHEMA_ID`

## `chio.transaction-passport.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:184` `CHIO_TRANSACTION_PASSPORT_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:1` `TRANSACTION_PASSPORT_SCHEMA_ID`
- `crates/products/chio-cli/src/cli/dispatch/proof/assemble.rs:4` `TRANSACTION_PASSPORT_SCHEMA`

## `chio.transaction.claim-set.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:186` `CHIO_TRANSACTION_CLAIM_SET_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:3` `TRANSACTION_CLAIM_SET_SCHEMA_ID`
- `crates/products/chio-cli/src/cli/dispatch/proof/assemble.rs:6` `TRANSACTION_CLAIM_SET_SCHEMA`

## `chio.transaction.evidence-graph.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:185` `CHIO_TRANSACTION_EVIDENCE_GRAPH_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:2` `TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID`
- `crates/products/chio-cli/src/cli/dispatch/proof/assemble.rs:5` `TRANSACTION_EVIDENCE_GRAPH_SCHEMA`

## `chio.transaction.verifier-policy.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:187` `CHIO_TRANSACTION_VERIFIER_POLICY_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:4` `TRANSACTION_VERIFIER_POLICY_SCHEMA_ID`
- `crates/products/chio-cli/src/cli/dispatch/proof/assemble.rs:7` `TRANSACTION_VERIFIER_POLICY_SCHEMA`

## `chio.transparency.inclusion-proof.v1` (3 declarations, 3 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:237` `CHIO_TRANSPARENCY_INCLUSION_PROOF_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/minimal.rs:796` `TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1_ID`
- `crates/trust/chio-selective-disclosure/src/lib.rs:102` `TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1`

## `chio-finding/v1/challenge.schema.json` (2 declarations, 2 crates)

- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_handlers.rs:32` `FINDING_CHALLENGE_SCHEMA_LABEL`
- `crates/products/chio-cli/src/cli/dispatch/finding/challenge.rs:21` `FINDING_CHALLENGE_SCHEMA_LABEL`

## `chio-finding/v1/finding.schema.json` (2 declarations, 2 crates)

- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_handlers.rs:33` `FINDING_SCHEMA_LABEL`
- `crates/products/chio-cli/src/cli/dispatch/finding/verify.rs:34` `FINDING_SCHEMA_LABEL`

## `chio.active-response-policy-authority.v2` (2 declarations, 2 crates)

- `crates/platform/chio-control-plane/src/security/active_response_authority.rs:38` `ACTIVE_RESPONSE_AUTHORITY_SCHEMA`
- `crates/security/chio-active-response-authority/src/config.rs:23` `ACTIVE_RESPONSE_AUTHORITY_PROTOCOL`

## `chio.anchor-inclusion-proof.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:29` `CHIO_ANCHOR_INCLUSION_PROOF_V1_SCHEMA`
- `crates/economy/chio-web3/src/anchors.rs:21` `CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA_V1`

## `chio.anchor-inclusion-proof.v2` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:30` `CHIO_ANCHOR_INCLUSION_PROOF_V2_SCHEMA`
- `crates/economy/chio-web3/src/anchors.rs:22` `CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA_V2`

## `chio.anchor-proof-bundle.v2` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:32` `CHIO_ANCHOR_PROOF_BUNDLE_V2_SCHEMA`
- `crates/economy/chio-anchor/src/bundle.rs:13` `CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA_V2`

## `chio.attest.buyer-attestation-packet.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:80` `CHIO_ATTEST_BUYER_ATTESTATION_PACKET_SCHEMA`
- `crates/trust/chio-attest-buyer/src/schemas.rs:1` `CHIO_ATTEST_BUYER_ATTESTATION_PACKET_SCHEMA`

## `chio.attest.buyer-attestation-review-package.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:87` `CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA`
- `crates/trust/chio-attest-buyer/src/schemas.rs:3` `CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA`

## `chio.attest.buyer-attestation-review-report.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:91` `CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA`
- `crates/trust/chio-attest-buyer/src/schemas.rs:5` `CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA`

## `chio.attest.buyer-attestation-verification-report.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:83` `CHIO_ATTEST_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA`
- `crates/trust/chio-attest-buyer/src/schemas.rs:7` `CHIO_ATTEST_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA`

## `chio.attest.selective-disclosure-proof.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:229` `CHIO_ATTEST_SELECTIVE_DISCLOSURE_PROOF_V1_SCHEMA`
- `crates/trust/chio-selective-disclosure/src/lib.rs:64` `SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1`

## `chio.bbs-projection.manifest.v2` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:231` `CHIO_BBS_PROJECTION_MANIFEST_V2_SCHEMA`
- `crates/trust/chio-selective-disclosure/src/projection_manifest.rs:4` `BBS_PROJECTION_MANIFEST_SCHEMA_V2`

## `chio.bbs-projection.receipt.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/receipt/signing.rs:21` `CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1`
- `crates/trust/chio-selective-disclosure/src/lib.rs:58` `PROJECTION_VERSION_RECEIPT_V1`

## `chio.bilateral-signature-slice.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:35` `CHIO_BILATERAL_SIGNATURE_SLICE_V1_SCHEMA`
- `crates/trust/chio-federation/src/bilateral_dsse/types.rs:16` `PREDICATE_TYPE_BILATERAL`

## `chio.channel.close.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:71` `CHIO_CHANNEL_CLOSE_V1_SCHEMA`
- `crates/economy/chio-settle/src/channel/close.rs:17` `CHANNEL_CLOSE_SCHEMA`

## `chio.channel.dispute.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:72` `CHIO_CHANNEL_DISPUTE_V1_SCHEMA`
- `crates/economy/chio-settle/src/channel/dispute.rs:12` `CHANNEL_DISPUTE_SCHEMA`

## `chio.channel.funding-acknowledgement.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:66` `CHIO_CHANNEL_FUNDING_ACKNOWLEDGEMENT_V1_SCHEMA`
- `crates/economy/chio-settle/src/channel/open.rs:19` `CHANNEL_FUNDING_ACKNOWLEDGEMENT_SCHEMA`

## `chio.channel.funding-evidence.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:64` `CHIO_CHANNEL_FUNDING_EVIDENCE_V1_SCHEMA`
- `crates/economy/chio-settle/src/channel/funding.rs:11` `CHANNEL_FUNDING_EVIDENCE_SCHEMA`

## `chio.channel.open-intent.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:65` `CHIO_CHANNEL_OPEN_INTENT_V1_SCHEMA`
- `crates/economy/chio-settle/src/channel/open.rs:18` `CHANNEL_OPEN_INTENT_SCHEMA`

## `chio.channel.open.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:68` `CHIO_CHANNEL_OPEN_V1_SCHEMA`
- `crates/economy/chio-settle/src/channel/open.rs:20` `CHANNEL_OPEN_SCHEMA`

## `chio.channel.reservation.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:69` `CHIO_CHANNEL_RESERVATION_V1_SCHEMA`
- `crates/economy/chio-settle/src/channel/reservation.rs:21` `CHANNEL_RESERVATION_SCHEMA`

## `chio.channel.state.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:70` `CHIO_CHANNEL_STATE_V1_SCHEMA`
- `crates/economy/chio-settle/src/channel/state.rs:22` `CHANNEL_STATE_SCHEMA`

## `chio.channel.terminal-outcome-commitment.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:75` `CHIO_CHANNEL_TERMINAL_OUTCOME_COMMITMENT_V1_SCHEMA`
- `crates/economy/chio-settle/src/channel/terminal_outcome.rs:12` `CHANNEL_TERMINAL_OUTCOME_COMMITMENT_SCHEMA`

## `chio.clearing.atom-transformation.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:55` `CHIO_CLEARING_ATOM_TRANSFORMATION_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/mod.rs:30` `CLEARING_TRANSFORMATION_SCHEMA`

## `chio.clearing.input-manifest.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:45` `CHIO_CLEARING_INPUT_MANIFEST_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/mod.rs:26` `CLEARING_INPUT_MANIFEST_SCHEMA`

## `chio.clearing.netting-round-core.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:46` `CHIO_CLEARING_NETTING_ROUND_CORE_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/mod.rs:27` `CLEARING_ROUND_CORE_SCHEMA`

## `chio.clearing.output-manifest.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:57` `CHIO_CLEARING_OUTPUT_MANIFEST_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/mod.rs:31` `CLEARING_OUTPUT_MANIFEST_SCHEMA`

## `chio.clearing.participant-acceptance.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:58` `CHIO_CLEARING_PARTICIPANT_ACCEPTANCE_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/mod.rs:32` `CLEARING_PARTICIPANT_ACCEPTANCE_SCHEMA`

## `chio.clearing.participant-snapshot-acknowledgement.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:43` `CHIO_CLEARING_PARTICIPANT_SNAPSHOT_ACKNOWLEDGEMENT_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/mod.rs:24` `CLEARING_PARTICIPANT_SNAPSHOT_ACKNOWLEDGEMENT_SCHEMA`

## `chio.clearing.participant-snapshot.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:41` `CHIO_CLEARING_PARTICIPANT_SNAPSHOT_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/mod.rs:23` `CLEARING_PARTICIPANT_SNAPSHOT_SCHEMA`

## `chio.clearing.participant-statement.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:47` `CHIO_CLEARING_PARTICIPANT_STATEMENT_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/mod.rs:28` `CLEARING_PARTICIPANT_STATEMENT_SCHEMA`

## `chio.clearing.round-abort.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:63` `CHIO_CLEARING_ROUND_ABORT_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/mod.rs:35` `CLEARING_ROUND_ABORT_SCHEMA`

## `chio.clearing.round-finalization.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:60` `CHIO_CLEARING_ROUND_FINALIZATION_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/mod.rs:33` `CLEARING_ROUND_FINALIZATION_SCHEMA`

## `chio.clearing.round-satisfaction.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:52` `CHIO_CLEARING_ROUND_SATISFACTION_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/lifecycle/satisfaction.rs:3` `CLEARING_ROUND_SATISFACTION_SCHEMA`

## `chio.clearing.settlement-intent.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:49` `CHIO_CLEARING_SETTLEMENT_INTENT_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/mod.rs:29` `CLEARING_SETTLEMENT_INTENT_SCHEMA`

## `chio.clearing.settlement-reconciliation.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:50` `CHIO_CLEARING_SETTLEMENT_RECONCILIATION_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/lifecycle/reconciliation.rs:8` `CLEARING_SETTLEMENT_RECONCILIATION_SCHEMA`

## `chio.clearing.zero-dispatch-proof.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:61` `CHIO_CLEARING_ZERO_DISPATCH_PROOF_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/mod.rs:34` `CLEARING_ZERO_DISPATCH_PROOF_SCHEMA`

## `chio.clearing.zero-intent-reconciliation.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:53` `CHIO_CLEARING_ZERO_INTENT_RECONCILIATION_V1_SCHEMA`
- `crates/economy/chio-credit/src/clearing/lifecycle/zero_intent.rs:3` `CLEARING_ZERO_INTENT_RECONCILIATION_SCHEMA`

## `chio.commerce.event-log.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:198` `CHIO_COMMERCE_EVENT_LOG_V1_SCHEMA`
- `crates/platform/chio-commerce-order/src/ids.rs:2` `COMMERCE_EVENT_LOG_SCHEMA_ID`

## `chio.commerce.federation-trust-bundle.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:207` `CHIO_COMMERCE_FEDERATION_TRUST_BUNDLE_V1_SCHEMA`
- `crates/platform/chio-commerce-order/src/ids.rs:10` `COMMERCE_FEDERATION_TRUST_BUNDLE_SCHEMA_ID`

## `chio.commerce.mandate-allowance-ledger.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:200` `CHIO_COMMERCE_MANDATE_ALLOWANCE_LEDGER_V1_SCHEMA`
- `crates/platform/chio-commerce-order/src/ids.rs:4` `COMMERCE_MANDATE_ALLOWANCE_LEDGER_SCHEMA_ID`

## `chio.commerce.order-context.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:197` `CHIO_COMMERCE_ORDER_CONTEXT_V1_SCHEMA`
- `crates/platform/chio-commerce-order/src/ids.rs:1` `COMMERCE_ORDER_CONTEXT_SCHEMA_ID`

## `chio.commerce.order-passport.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:209` `CHIO_COMMERCE_ORDER_PASSPORT_V1_SCHEMA`
- `crates/platform/chio-commerce-order/src/ids.rs:12` `COMMERCE_ORDER_PASSPORT_SCHEMA_ID`

## `chio.commerce.payment-lifecycle.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:199` `CHIO_COMMERCE_PAYMENT_LIFECYCLE_V1_SCHEMA`
- `crates/platform/chio-commerce-order/src/ids.rs:3` `COMMERCE_PAYMENT_LIFECYCLE_SCHEMA_ID`

## `chio.commerce.protocol-payload.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:202` `CHIO_COMMERCE_PROTOCOL_PAYLOAD_V1_SCHEMA`
- `crates/platform/chio-commerce-order/src/ids.rs:6` `COMMERCE_PROTOCOL_PAYLOAD_SCHEMA_ID`

## `chio.commerce.provider-passport.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:204` `CHIO_COMMERCE_PROVIDER_PASSPORT_V1_SCHEMA`
- `crates/platform/chio-commerce-order/src/ids.rs:8` `COMMERCE_PROVIDER_PASSPORT_SCHEMA_ID`

## `chio.commerce.reputation-snapshot.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:205` `CHIO_COMMERCE_REPUTATION_SNAPSHOT_V1_SCHEMA`
- `crates/platform/chio-commerce-order/src/ids.rs:9` `COMMERCE_REPUTATION_SNAPSHOT_SCHEMA_ID`

## `chio.commerce.settlement-packet.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:203` `CHIO_COMMERCE_SETTLEMENT_PACKET_V1_SCHEMA`
- `crates/platform/chio-commerce-order/src/ids.rs:7` `COMMERCE_SETTLEMENT_PACKET_SCHEMA_ID`

## `chio.crypto.verification-context.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:219` `CHIO_CRYPTO_VERIFICATION_CONTEXT_V1_SCHEMA`
- `crates/trust/chio-selective-disclosure/src/crypto_context/types.rs:10` `CRYPTO_VERIFICATION_CONTEXT_SCHEMA_V1`

## `chio.disclosure.capsule.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:232` `CHIO_DISCLOSURE_CAPSULE_V1_SCHEMA`
- `crates/trust/chio-disclosure-lineage/src/types.rs:5` `DISCLOSURE_CAPSULE_SCHEMA_V1`

## `chio.disclosure.crypto-context-report.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:227` `CHIO_DISCLOSURE_CRYPTO_CONTEXT_REPORT_V1_SCHEMA`
- `crates/trust/chio-disclosure-lineage/src/types.rs:3` `DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1`

## `chio.disclosure.leakage-ledger.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:234` `CHIO_DISCLOSURE_LEAKAGE_LEDGER_V1_SCHEMA`
- `crates/trust/chio-disclosure-lineage/src/types.rs:7` `DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1`

## `chio.disclosure.lineage-verifier-report.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:235` `CHIO_DISCLOSURE_LINEAGE_VERIFIER_REPORT_V1_SCHEMA`
- `crates/trust/chio-disclosure-lineage/src/types.rs:8` `DISCLOSURE_LINEAGE_VERIFIER_REPORT_SCHEMA_V1`

## `chio.disclosure.verifier-privacy-profile.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:225` `CHIO_DISCLOSURE_VERIFIER_PRIVACY_PROFILE_V1_SCHEMA`
- `crates/trust/chio-disclosure-lineage/src/types.rs:10` `DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1`

## `chio.econsim.qualification-matrix.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:160` `CHIO_ECONSIM_QUALIFICATION_MATRIX_V1_SCHEMA`
- `crates/tooling/chio-conformance/src/econsim.rs:8` `ECONSIM_QUALIFICATION_MATRIX_SCHEMA`

## `chio.federation.bilateral-invocation.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:69` `CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA`
- `crates/trust/chio-attest-buyer/src/schemas.rs:11` `CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA`

## `chio.federation.cross-boundary-admission-report.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:65` `CHIO_FEDERATION_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA`
- `crates/trust/chio-federation/src/treaty.rs:12` `CHIO_FEDERATION_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA`

## `chio.federation.cross-kernel-continuation.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:57` `CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA`
- `crates/trust/chio-attest-buyer/src/schemas.rs:13` `CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA`

## `chio.federation.governance-ladder-manifest.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:50` `CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA`
- `crates/trust/chio-federation/src/treaty.rs:7` `CHIO_FEDERATION_GOVERNANCE_LADDER_MANIFEST_SCHEMA`

## `chio.federation.ladder-intersection.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:54` `CHIO_FEDERATION_LADDER_INTERSECTION_SCHEMA`
- `crates/trust/chio-federation/src/treaty.rs:10` `CHIO_FEDERATION_LADDER_INTERSECTION_SCHEMA`

## `chio.federation.receipt-lineage-bundle.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:72` `CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA`
- `crates/trust/chio-attest-buyer/src/schemas.rs:15` `CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA`

## `chio.federation.receipt-lineage-statement.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:61` `CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA`
- `crates/trust/chio-attest-buyer/src/schemas.rs:17` `CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA`

## `chio.federation.treaty-scope.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:52` `CHIO_FEDERATION_TREATY_SCOPE_SCHEMA`
- `crates/trust/chio-federation/src/treaty.rs:9` `CHIO_FEDERATION_TREATY_SCOPE_SCHEMA`

## `chio.financial-agent-passport-presentation-challenge.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:89` `CHIO_FINANCIAL_AGENT_PASSPORT_PRESENTATION_CHALLENGE_V1_SCHEMA`
- `crates/trust/chio-credentials/src/financial.rs:4` `FINANCIAL_PASSPORT_PRESENTATION_CHALLENGE_SCHEMA_V1`

## `chio.financial-agent-passport.source-manifest.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:87` `CHIO_FINANCIAL_AGENT_PASSPORT_SOURCE_MANIFEST_V1_SCHEMA`
- `crates/trust/chio-credentials/src/financial.rs:2` `FINANCIAL_AGENT_PASSPORT_SOURCE_MANIFEST_SCHEMA_V1`

## `chio.fincred.credit-scorecard.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:77` `CHIO_FINCRED_CREDIT_SCORECARD_V1_SCHEMA`
- `crates/economy/chio-fincred/src/lib.rs:13` `FINANCIAL_CREDENTIAL_SCHEMA_CREDIT_SCORECARD_V1`

## `chio.fincred.exposure-history.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:78` `CHIO_FINCRED_EXPOSURE_HISTORY_V1_SCHEMA`
- `crates/economy/chio-fincred/src/lib.rs:15` `FINANCIAL_CREDENTIAL_SCHEMA_EXPOSURE_HISTORY_V1`

## `chio.fincred.loss-history.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:82` `CHIO_FINCRED_LOSS_HISTORY_V1_SCHEMA`
- `crates/economy/chio-fincred/src/lib.rs:20` `FINANCIAL_CREDENTIAL_SCHEMA_LOSS_HISTORY_V1`

## `chio.fincred.premium-history.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:81` `CHIO_FINCRED_PREMIUM_HISTORY_V1_SCHEMA`
- `crates/economy/chio-fincred/src/lib.rs:19` `FINANCIAL_CREDENTIAL_SCHEMA_PREMIUM_HISTORY_V1`

## `chio.fincred.settlement-reliability.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:79` `CHIO_FINCRED_SETTLEMENT_RELIABILITY_V1_SCHEMA`
- `crates/economy/chio-fincred/src/lib.rs:17` `FINANCIAL_CREDENTIAL_SCHEMA_SETTLEMENT_RELIABILITY_V1`

## `chio.fincred.source-checkpoint.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:84` `CHIO_FINCRED_SOURCE_CHECKPOINT_V1_SCHEMA`
- `crates/economy/chio-fincred/src/lib.rs:23` `FINANCIAL_SOURCE_CHECKPOINT_SCHEMA_V1`

## `chio.fincred.source-completeness-attestation.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:85` `CHIO_FINCRED_SOURCE_COMPLETENESS_ATTESTATION_V1_SCHEMA`
- `crates/economy/chio-fincred/src/lib.rs:21` `FINANCIAL_SOURCE_COMPLETENESS_ATTESTATION_SCHEMA_V1`

## `chio.fincred.source-member.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:83` `CHIO_FINCRED_SOURCE_MEMBER_V1_SCHEMA`
- `crates/economy/chio-fincred/src/lib.rs:24` `FINANCIAL_SOURCE_MEMBER_SCHEMA_V1`

## `chio.finding.claim-allocation.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:117` `CHIO_FINDING_CLAIM_ALLOCATION_V1_SCHEMA`
- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs:183` `ALLOCATION_DIGEST_DOMAIN`

## `chio.finding.effect.fee.v1` (2 declarations, 2 crates)

- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs:158` `EFFECT_FEE_DOMAIN`
- `crates/platform/chio-store-sqlite/src/finding_challenge_store.rs:142` `EFFECT_FEE_DOMAIN`

## `chio.finding.effect.seller-impair.v1` (2 declarations, 2 crates)

- `crates/economy/chio-finding/src/challenge_enforcement.rs:46` `SELLER_IMPAIR_INTENT_DOMAIN`
- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs:152` `EFFECT_SELLER_IMPAIR_DOMAIN`

## `chio.finding.liability.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:126` `CHIO_FINDING_LIABILITY_V1_SCHEMA`
- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs:149` `LIABILITY_DOMAIN`

## `chio.finding.purchase-result.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:136` `CHIO_FINDING_PURCHASE_RESULT_V1_SCHEMA`
- `crates/platform/chio-control-plane/src/trust_control/finding_purchase_routes.rs:52` `FINDING_PURCHASE_RESULT_SCHEMA`

## `chio.finding.verified-fix-submission.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:141` `CHIO_FINDING_VERIFIED_FIX_SUBMISSION_V1_SCHEMA`
- `crates/platform/chio-control-plane/src/trust_control/finding_operator_seller_routes.rs:18` `FINDING_VERIFIED_FIX_SUBMISSION_SCHEMA`

## `chio.fiscal.activation.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:156` `CHIO_FISCAL_ACTIVATION_V1_SCHEMA`
- `crates/economy/chio-fiscal/src/lifecycle/activation.rs:22` `FISCAL_ACTIVATION_SCHEMA`

## `chio.fiscal.approval.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:155` `CHIO_FISCAL_APPROVAL_V1_SCHEMA`
- `crates/economy/chio-fiscal/src/lifecycle/activation.rs:21` `FISCAL_APPROVAL_SCHEMA`

## `chio.fiscal.charter.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:151` `CHIO_FISCAL_CHARTER_V1_SCHEMA`
- `crates/economy/chio-fiscal/src/fiscal.rs:12` `FISCAL_CHARTER_SCHEMA`

## `chio.fiscal.consumer-readiness.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:157` `CHIO_FISCAL_CONSUMER_READINESS_V1_SCHEMA`
- `crates/economy/chio-fiscal/src/lifecycle/readiness.rs:13` `FISCAL_RUNTIME_READINESS_SCHEMA`

## `chio.fiscal.continuity-checkpoint.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:158` `CHIO_FISCAL_CONTINUITY_CHECKPOINT_V1_SCHEMA`
- `crates/economy/chio-fiscal/src/lifecycle/continuity.rs:25` `FISCAL_CONTINUITY_CHECKPOINT_SCHEMA`

## `chio.fiscal.proposal-admission.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:154` `CHIO_FISCAL_PROPOSAL_ADMISSION_V1_SCHEMA`
- `crates/economy/chio-fiscal/src/lifecycle/proposal.rs:19` `FISCAL_PROPOSAL_ADMISSION_SCHEMA`

## `chio.fiscal.proposal.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:153` `CHIO_FISCAL_PROPOSAL_V1_SCHEMA`
- `crates/economy/chio-fiscal/src/lifecycle/proposal.rs:18` `FISCAL_PROPOSAL_SCHEMA`

## `chio.fiscal.schedule.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:152` `CHIO_FISCAL_SCHEDULE_V1_SCHEMA`
- `crates/economy/chio-fiscal/src/fiscal.rs:13` `FISCAL_SCHEDULE_SCHEMA`

## `chio.frost.authorization-slot-checkpoint.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:36` `CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_V1_SCHEMA`
- `crates/trust/chio-federation/src/frost/verify.rs:18` `CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA`

## `chio.frost.authorization.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:38` `CHIO_FROST_AUTHORIZATION_V1_SCHEMA`
- `crates/trust/chio-federation/src/frost/verify.rs:17` `CHIO_FROST_AUTHORIZATION_SCHEMA`

## `chio.frost.epoch-checkpoint.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:39` `CHIO_FROST_EPOCH_CHECKPOINT_V1_SCHEMA`
- `crates/trust/chio-federation/src/frost/roster.rs:15` `CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA`

## `chio.frost.roster.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:40` `CHIO_FROST_ROSTER_V1_SCHEMA`
- `crates/trust/chio-federation/src/frost/roster.rs:14` `CHIO_FROST_ROSTER_SCHEMA`

## `chio.lineage.signed-subgraph.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:233` `CHIO_LINEAGE_SIGNED_SUBGRAPH_V1_SCHEMA`
- `crates/trust/chio-disclosure-lineage/src/types.rs:6` `LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1`

## `chio.native-flow-dispatch-policy.v1` (2 declarations, 2 crates)

- `crates/platform/chio-control-plane/src/security/adapters/native_flow/policy.rs:10` `SCHEMA`
- `crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/policy.rs:6` `POLICY_SCHEMA`

## `chio.native-flow-dispatch-policy.v2` (2 declarations, 2 crates)

- `crates/platform/chio-control-plane/src/security/adapters/native_flow/policy.rs:11` `DECLASSIFIED_SCHEMA`
- `crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/policy.rs:7` `DECLASSIFIED_POLICY_SCHEMA`

## `chio.obligation.status-proof.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:162` `CHIO_OBLIGATION_STATUS_PROOF_V1_SCHEMA`
- `crates/economy/chio-credit/src/obligation/status.rs:15` `OBLIGATION_STATUS_PROOF_SCHEMA`

## `chio.oracle-conversion-evidence.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/oracle.rs:7` `CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA`
- `crates/economy/chio-web3/src/anchors.rs:24` `CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA`

## `chio.parametric.policy.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:183` `CHIO_PARAMETRIC_POLICY_V1_SCHEMA`
- `crates/economy/chio-market/src/parametric.rs:23` `PARAMETRIC_POLICY_SCHEMA`

## `chio.policy.activation-receipt.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:241` `CHIO_POLICY_ACTIVATION_RECEIPT_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:9` `POLICY_ACTIVATION_RECEIPT_SCHEMA_ID`

## `chio.proof.first-run.capability-proof.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:283` `CHIO_PROOF_FIRST_RUN_CAPABILITY_PROOF_V1_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:48` `PROOF_ROOM_FIRST_RUN_CAPABILITY_PROOF_SCHEMA`

## `chio.proof.first-run.command-log.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:288` `CHIO_PROOF_FIRST_RUN_COMMAND_LOG_V1_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:52` `PROOF_ROOM_FIRST_RUN_COMMAND_LOG_SCHEMA`

## `chio.proof.first-run.guard-report.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:285` `CHIO_PROOF_FIRST_RUN_GUARD_REPORT_V1_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:50` `PROOF_ROOM_FIRST_RUN_GUARD_REPORT_SCHEMA`

## `chio.proof.release-truth.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:282` `CHIO_PROOF_RELEASE_TRUTH_V1_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:47` `PROOF_ROOM_RELEASE_TRUTH_SCHEMA`

## `chio.public-settlement-verifier-report.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:298` `CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_V1_SCHEMA`
- `crates/economy/chio-web3/src/settlement_proof.rs:21` `CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_SCHEMA`

## `chio.registry.market-penalty.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:150` `CHIO_REGISTRY_MARKET_PENALTY_V1_SCHEMA`
- `crates/economy/chio-open-market/src/penalty.rs:17` `OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA`

## `chio.response.digest.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:196` `CHIO_RESPONSE_DIGEST_V1_SCHEMA`
- `crates/products/chio-proof-room/src/lib.rs:55` `TRANSACTION_RESPONSE_DIGEST_SCHEMA`

## `chio.risk.collateral-position-report.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:252` `CHIO_RISK_COLLATERAL_POSITION_REPORT_V1_SCHEMA`
- `crates/platform/chio-trust-market-context/src/evidence.rs:14` `RISK_COLLATERAL_POSITION_REPORT_SCHEMA`

## `chio.runtime-attestation.enterprise-verifier.json.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/runtime_attestation.rs:16` `ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA`
- `crates/economy/chio-appraisal/src/types.rs:20` `ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA`

## `chio.runtime-attestation.google-confidential-vm.jwt.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/runtime_attestation.rs:14` `GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA`
- `crates/economy/chio-appraisal/src/types.rs:18` `GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA`

## `chio.runtime-replay-source-seal.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-kernel/src/admission_operation/runtime_replay.rs:14` `SOURCE_SCHEMA`
- `crates/kernel/chio-runtime-core/src/replay_source.rs:15` `SOURCE_SCHEMA`

## `chio.runtime.admission-bundle.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:2` `CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:92` `CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA`

## `chio.runtime.admission-profile.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:1` `CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:91` `CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA`

## `chio.runtime.admission-report.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:4` `CHIO_RUNTIME_ADMISSION_REPORT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:94` `CHIO_RUNTIME_ADMISSION_REPORT_SCHEMA`

## `chio.runtime.admission-store.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:13` `CHIO_RUNTIME_ADMISSION_STORE_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:103` `CHIO_RUNTIME_ADMISSION_STORE_SCHEMA`

## `chio.runtime.artifact-retention-plan.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:40` `CHIO_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:128` `CHIO_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA`

## `chio.runtime.artifact-retention-profile.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:38` `CHIO_RUNTIME_ARTIFACT_RETENTION_PROFILE_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:126` `CHIO_RUNTIME_ARTIFACT_RETENTION_PROFILE_SCHEMA`

## `chio.runtime.attack-simulation-report.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:248` `CHIO_RUNTIME_ATTACK_SIMULATION_REPORT_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:17` `RUNTIME_ATTACK_SIMULATION_REPORT_SCHEMA_ID`

## `chio.runtime.chaos-run-report.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:250` `CHIO_RUNTIME_CHAOS_RUN_REPORT_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:19` `RUNTIME_CHAOS_RUN_REPORT_SCHEMA_ID`

## `chio.runtime.evidence-sink-health-report.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:35` `CHIO_RUNTIME_EVIDENCE_SINK_HEALTH_REPORT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:123` `CHIO_RUNTIME_EVIDENCE_SINK_HEALTH_REPORT_SCHEMA`

## `chio.runtime.execution-lease.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:242` `CHIO_RUNTIME_EXECUTION_LEASE_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:10` `RUNTIME_EXECUTION_LEASE_SCHEMA_ID`

## `chio.runtime.ops-status-report.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:45` `CHIO_RUNTIME_OPS_STATUS_REPORT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:133` `CHIO_RUNTIME_OPS_STATUS_REPORT_SCHEMA`

## `chio.runtime.orchestration-plan.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:20` `CHIO_RUNTIME_ORCHESTRATION_PLAN_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:110` `CHIO_RUNTIME_ORCHESTRATION_PLAN_SCHEMA`

## `chio.runtime.orchestration-profile.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:21` `CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:111` `CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA`

## `chio.runtime.orchestration-resume-plan.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:25` `CHIO_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:115` `CHIO_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA`

## `chio.runtime.orchestration-run-report.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:23` `CHIO_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:113` `CHIO_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA`

## `chio.runtime.orchestration-status-report.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:27` `CHIO_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:117` `CHIO_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA`

## `chio.runtime.peer-weights.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:18` `CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:108` `CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA`

## `chio.runtime.pheromone-policy-decision.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:16` `CHIO_RUNTIME_PHEROMONE_POLICY_DECISION_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:106` `CHIO_RUNTIME_PHEROMONE_POLICY_DECISION_SCHEMA`

## `chio.runtime.pheromone-policy.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:15` `CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:105` `CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA`

## `chio.runtime.proof-drift-report.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:29` `CHIO_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:119` `CHIO_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA`

## `chio.runtime.provider-bindings.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:42` `CHIO_RUNTIME_PROVIDER_BINDINGS_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:130` `CHIO_RUNTIME_PROVIDER_BINDINGS_SCHEMA`

## `chio.runtime.provider-health-report.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:43` `CHIO_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:131` `CHIO_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA`

## `chio.runtime.recovery-drill-report.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:37` `CHIO_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:125` `CHIO_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA`

## `chio.runtime.revocation-freshness-proof.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:245` `CHIO_RUNTIME_REVOCATION_FRESHNESS_PROOF_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:14` `RUNTIME_REVOCATION_FRESHNESS_PROOF_SCHEMA_ID`

## `chio.runtime.run-contract.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:22` `CHIO_RUNTIME_RUN_CONTRACT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:112` `CHIO_RUNTIME_RUN_CONTRACT_SCHEMA`

## `chio.runtime.run-lease.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:33` `CHIO_RUNTIME_RUN_LEASE_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:121` `CHIO_RUNTIME_RUN_LEASE_SCHEMA`

## `chio.runtime.sandbox-attestation.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:247` `CHIO_RUNTIME_SANDBOX_ATTESTATION_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:16` `RUNTIME_SANDBOX_ATTESTATION_SCHEMA_ID`

## `chio.runtime.scheduler-tick-report.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:34` `CHIO_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:122` `CHIO_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA`

## `chio.runtime.step-evidence.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:6` `CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:96` `CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA`

## `chio.runtime.supervisor-profile.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:32` `CHIO_RUNTIME_SUPERVISOR_PROFILE_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:120` `CHIO_RUNTIME_SUPERVISOR_PROFILE_SCHEMA`

## `chio.runtime.terminal-receipt-signature.v1` (2 declarations, 2 crates)

- `crates/platform/chio-transaction-passport/src/runtime_security/artifacts.rs:25` `RUNTIME_TERMINAL_RECEIPT_SIGNATURE_SCHEMA`
- `crates/products/chio-proof-room/src/receipt_coverage.rs:11` `RUNTIME_TERMINAL_RECEIPT_SIGNATURE_SCHEMA`

## `chio.runtime.tool-server-ack.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:243` `CHIO_RUNTIME_TOOL_SERVER_ACK_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:11` `RUNTIME_TOOL_SERVER_ACK_SCHEMA_ID`

## `chio.runtime.trusted-verifiers.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:14` `CHIO_RUNTIME_TRUSTED_VERIFIERS_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:104` `CHIO_RUNTIME_TRUSTED_VERIFIERS_SCHEMA`

## `chio.runtime.verifier-trust-bundle.v1` (2 declarations, 2 crates)

- `crates/kernel/chio-runtime-core/src/schema.rs:3` `CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA`
- `crates/kernel/chio-runtime/src/lib.rs:93` `CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA`

## `chio.swarm.authority-verifier-report.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:310` `CHIO_SWARM_AUTHORITY_VERIFIER_REPORT_V1_SCHEMA`
- `crates/kernel/chio-swarm-authority/src/types.rs:13` `CHIO_SWARM_AUTHORITY_VERIFIER_REPORT_SCHEMA`

## `chio.swarm.continuation-token.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:301` `CHIO_SWARM_CONTINUATION_TOKEN_V1_SCHEMA`
- `crates/kernel/chio-swarm-authority/src/types.rs:5` `CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA`

## `chio.swarm.delegation-witness-chain.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:302` `CHIO_SWARM_DELEGATION_WITNESS_CHAIN_V1_SCHEMA`
- `crates/kernel/chio-swarm-authority/src/types.rs:6` `CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA`

## `chio.swarm.revocation-epoch.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:309` `CHIO_SWARM_REVOCATION_EPOCH_V1_SCHEMA`
- `crates/kernel/chio-swarm-authority/src/types.rs:11` `CHIO_SWARM_REVOCATION_EPOCH_SCHEMA`

## `chio.swarm.terminal-graph-receipt.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:306` `CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_V1_SCHEMA`
- `crates/kernel/chio-swarm-authority/src/types.rs:12` `CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA`

## `chio.transaction.runtime-security-report.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:189` `CHIO_TRANSACTION_RUNTIME_SECURITY_REPORT_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:6` `TRANSACTION_RUNTIME_SECURITY_REPORT_SCHEMA_ID`

## `chio.transaction.verifier-report.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:188` `CHIO_TRANSACTION_VERIFIER_REPORT_V1_SCHEMA`
- `crates/platform/chio-transaction-passport/src/ids.rs:5` `TRANSACTION_VERIFIER_REPORT_SCHEMA_ID`

## `chio.transparency.inclusion-proof.v2` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:239` `CHIO_TRANSPARENCY_INCLUSION_PROOF_V2_SCHEMA`
- `crates/platform/chio-transaction-passport/src/minimal.rs:797` `TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V2_ID`

## `chio.trust.key-state.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:220` `CHIO_TRUST_KEY_STATE_V1_SCHEMA`
- `crates/trust/chio-selective-disclosure/src/crypto_context/types.rs:11` `TRUST_KEY_STATE_SCHEMA_V1`

## `chio.trust.revocation-snapshot.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:221` `CHIO_TRUST_REVOCATION_SNAPSHOT_V1_SCHEMA`
- `crates/trust/chio-selective-disclosure/src/crypto_context/types.rs:12` `TRUST_REVOCATION_SNAPSHOT_SCHEMA_V1`

## `chio.verdict-matrix.scenario.v1` (2 declarations, 1 crate)

- `crates/tooling/chio-conformance/verdict_matrix/drivers/lambda/src/lib.rs:43` `SCENARIO_SCHEMA`
- `crates/tooling/chio-conformance/verdict_matrix/src/lib.rs:8` `SCENARIO_SCHEMA`

## `chio.web3-settlement-dispatch.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:290` `CHIO_WEB3_SETTLEMENT_DISPATCH_V1_SCHEMA`
- `crates/economy/chio-web3/src/settlement.rs:24` `CHIO_WEB3_SETTLEMENT_DISPATCH_V1_SCHEMA`

## `chio.web3-settlement-dispatch.v2` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:293` `CHIO_WEB3_SETTLEMENT_DISPATCH_V2_SCHEMA`
- `crates/economy/chio-web3/src/settlement.rs:25` `CHIO_WEB3_SETTLEMENT_DISPATCH_V2_SCHEMA`

## `chio.web3-settlement-execution-receipt.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:291` `CHIO_WEB3_SETTLEMENT_EXECUTION_RECEIPT_V1_SCHEMA`
- `crates/economy/chio-web3/src/settlement.rs:27` `CHIO_WEB3_SETTLEMENT_RECEIPT_V1_SCHEMA`

## `chio.workflow.preflight-plan.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:217` `CHIO_WORKFLOW_PREFLIGHT_PLAN_V1_SCHEMA`
- `crates/platform/chio-workflow-preflight/src/types.rs:3` `WORKFLOW_PREFLIGHT_PLAN_SCHEMA`

## `chio.workflow.preflight-report.v1` (2 declarations, 2 crates)

- `crates/core/chio-core-types/src/signed_artifact.rs:218` `CHIO_WORKFLOW_PREFLIGHT_REPORT_V1_SCHEMA`
- `crates/platform/chio-workflow-preflight/src/types.rs:4` `WORKFLOW_PREFLIGHT_REPORT_SCHEMA`
