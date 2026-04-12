# MERCURY Phase 2-3 Tickets

**Scope:** Phase 2 (Pilot Evidence Stack) and Phase 3 (Pilot Readiness and Proof Distribution)  
**Source of truth:** [MASTER_PROJECT.md](MASTER_PROJECT.md)

---

## Phase 2

### E-009: Replay / Shadow Ingestion

#### T-101: Ingestion adapter contract

- Define the input contract for replayed, mirrored, synthetic, and
  paper-trading events, including controlled release and rollback events.

#### T-102: Event normalization pipeline

- Normalize source events into the canonical MERCURY evidence input shape.

#### T-103: Ingestion idempotency tests

- Ensure duplicate event delivery does not corrupt the evidence chain.

#### T-103A: Recommendation-to-approval chronology tests

- Verify chronology across proposal, approval, release, rollback, exception,
  and downstream evidence events.

### E-010: Simulated Workflow Harness

#### T-104: Deterministic simulator

- Provide a deterministic workflow simulator for demos and test runs.

#### T-105: Seed datasets

- Create reusable pilot datasets covering common workflow patterns.

#### T-106: Harness CLI or runner

- Add a repeatable runner for end-to-end harness execution.

### E-011: Change-Control and Supervisory Attestation

#### T-107: Release and approval evidence type

- Implement release, rollback, approval, and override evidence structures.

#### T-108: Risk-check evidence type

- Implement structured recording of risk-check or supervisory results.

#### T-109: Change-review and rollback workflow tests

- Validate both pass and fail evidence paths across change review and rollback.

### E-012: Raw Artifact Retention

#### T-110: Artifact retention service

- Implement storage or reference persistence for raw source artifacts.

#### T-111: Artifact lifecycle policy

- Define retention classes, legal-hold behavior, archive paths, and retrieval
  rules.

#### T-112: Integrity failure handling

- Define behavior when an artifact is missing or integrity checks fail.

#### T-112A: Record taxonomy and communications policy

- Map retained artifacts and exports into convenience-copy, supervisory,
  regulated-record, and communications classes.

### E-013: Reconciliation and End-to-End Harness

#### T-113: Source ID reconciliation model

- Persist source-system IDs needed for investigation and downstream alignment.

#### T-114: End-to-end proof harness

- Build the full path from source event to receipt, checkpoint, and retrieval.

#### T-115: Pilot walkthrough dataset

- Create a reference run used in demo, docs, and pilot validation.

#### T-115A: Approval / override pilot dataset

- Create a canonical pilot dataset centered on release, rollback, approval,
  exception, and inquiry evidence.

---

## Phase 3

### E-014: Proof Package API

#### T-116: Receipt retrieval endpoint

- Serve receipts by stable ID and business identifiers.

#### T-117: Checkpoint and proof endpoints

- Serve checkpoints, inclusion proofs, and publication metadata.

#### T-118: Evidence bundle retrieval endpoint

- Provide controlled access to retained bundles or export packages.

#### T-118A: `Proof Package v1` export endpoint

- Provide a stable retrieval path for the canonical proof package.

#### T-118B: `Inquiry Package v1` export endpoint

- Provide a stable retrieval path for reviewed internal or external inquiry
  packages.

### E-015: Entitlement Model

#### T-119: Business entitlement schema

- Model account, desk, client, and reviewer access scopes.

#### T-120: Authorization middleware

- Enforce entitlement rules across retrieval paths.

#### T-121: Access audit logging

- Record retrieval and export activity for auditability.

#### T-121A: Audience and redaction enforcement

- Enforce audience-specific packaging and redaction policy at export time.

### E-016: Publication and External Witness

#### T-122: Checkpoint publication pipeline

- Publish checkpoints to the primary publication location.

#### T-123: External witness integration

- Add a second publication or witness step outside operator-only control.

#### T-124: Publication gap monitoring

- Detect missing or delayed publication events.

#### T-124A: Witness failure handling

- Define retry, degradation, and operator response behavior when witness steps
  fail.

### E-017: Deployment and Key Runbooks

#### T-125: Key onboarding runbook

- Document initial trust setup, rotation, and emergency handling.

#### T-126: Deployment runbook

- Document install, config, health checks, and degraded mode.

#### T-127: Backup and recovery runbook

- Document export, backup, restore, and verification after recovery.

#### T-127A: Legal-hold and prompt-production runbook

- Document how retained artifacts and prompts are preserved and produced under
  hold or inquiry conditions.

### E-018: Pilot Exit Package

#### T-128: Pilot report template

- Create the standard report format for design-partner readouts.

#### T-129: Conversion decision memo

- Standardize the output used to select the next funded integration path.

#### T-130: Pilot acceptance checklist

- Define the criteria that close the pilot successfully.

---

## Exit Criteria

Phase 2-3 is complete when:

- the full replay or shadow workflow produces verifiable release, rollback,
  approval, exception, or inquiry evidence
- the API can serve all proof material needed for external review
- publication includes an external witness or immutable step
- the team can support a design-partner pilot operationally
