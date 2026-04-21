# MERCURY Phase 0-1 Tickets

**Scope:** Phase 0 (Scope Lock and Reuse Map) and Phase 1 (Core Evidence and Verification)  
**Source of truth:** [MASTER_PROJECT.md](MASTER_PROJECT.md)

---

## Phase 0

### E-001: Chio Reuse Inventory

#### T-001: Receipt and checkpoint reuse map

- Identify Chio components reused directly for signing, receipt storage, and
  verification.

#### T-002: Gap list for MERCURY-specific logic

- Separate net-new MERCURY work from Chio infrastructure already available.

#### T-003: Reuse sign-off memo

- Publish the engineering note used to freeze the reuse plan.

### E-002: Canonical Evidence Object

#### T-004: Receipt metadata schema

- Define business identifiers, model metadata, policy references, and decision
  types.

#### T-005: Evidence-bundle reference schema

- Define bundle identifiers, integrity fields, and retention references.

#### T-006: Reconciliation metadata schema

- Define fields for upstream and downstream source-system linkage.

#### T-006A: Chronology and causality schema

- Define event ordering, stage markers, parent links, and ingest versus source
  timestamps.

#### T-006B: Sensitivity and disclosure schema

- Define sensitivity classes, disclosure policy hooks, and redaction metadata.

### E-003: Kernel Profile and Trust Assumptions

#### T-007: MERCURY kernel profile definition

- Specify signing, checkpoint, storage, and publication defaults for the
  product program.

#### T-008: Trust-boundary note

- Document what is trusted, partially trusted, and out of scope.

#### T-009: Operational assumptions review

- Confirm the profile aligns with deployment, key, and monitoring expectations.

#### T-009A: `Publication Profile v1`

- Freeze checkpoint continuity, witness, trust-anchor, and revocation semantics
  for exported proof material.

### E-004: Pilot Topology Definition

#### T-010: Workflow selection template

- Create a standard method for selecting the pilot workflow and source inputs.

#### T-011: Proof-boundary statement

- Publish the exact proof and non-proof claims used in pilot materials.

#### T-012: Pilot data and retention profile

- Define which artifacts must be retained for the pilot to be credible.

#### T-012A: First workflow selection pack

- Produce the signed-off workflow brief for the first governed change,
  release, rollback, exception, approval, or inquiry pilot.

---

## Phase 1

### E-005: `chio-mercury-core`

#### T-013: Core crate scaffold

- Create the crate and module structure for the MERCURY evidence model.

#### T-014: Canonical serialization and validation

- Implement deterministic serialization and validation helpers.

#### T-015: Receipt-construction tests

- Add tests for receipt construction using the canonical schema.

### E-006: Evidence Bundle Schema

#### T-016: Bundle manifest type

- Implement the bundle manifest and artifact reference structures.

#### T-017: Bundle hashing

- Implement integrity calculation for bundles and embedded references.

#### T-018: Bundle fixture set

- Add known-answer test fixtures for bundle verification.

#### T-018A: Redacted package fixture set

- Add fixtures covering audience-scoped redaction without breaking verification.

### E-007: Query Extensions

#### T-019: Business identifier filters

- Add query filters for workflow, account, desk, order, and strategy IDs.

#### T-020: Decision-type filters

- Support query by decision type and approval state.

#### T-021: Investigation query tests

- Validate the query layer against pilot-style investigation scenarios.

### E-008: Verifier Library and CLI

#### T-022: Verifier library surface

- Implement verification entry points for receipt, checkpoint, and bundle
  validation.

#### T-023: CLI commands and output

- Provide pass/fail, explain, and JSON output modes.

#### T-024: End-to-end verification fixture

- Add a fully working sample export package used by the CLI and docs.

#### T-024A: `Proof Package v1` contract

- Freeze the export contract used by the API, CLI, docs, and pilot materials.

---

## Exit Criteria

Phase 0-1 is complete when:

- the canonical evidence object is frozen
- `Proof Package v1` and `Publication Profile v1` are frozen
- the reuse map is accepted
- the verifier works end-to-end against known-answer fixtures
- business-identifier queries support pilot investigation workflows
