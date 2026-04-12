# MERCURY Cross-Cutting Tickets

**Scope:** Security, testing, operations, documentation, and release disciplines that span all phases

---

## Security and Trust

### X-001: Key management policy

- Define signing-key handling, rotation, recovery, and publication policy.

### X-002: Trust-anchor publication policy

- Standardize how trusted keys and rotation state are distributed.

### X-002A: Publication profile governance

- Govern `Publication Profile v1` changes, witness semantics, and continuity
  rules across releases.

### X-002B: Inquiry package governance

- Govern `Inquiry Package v1` semantics, disclosure metadata, and
  verifier-equivalence rules across releases.

### X-003: Security review checkpoints

- Add phase-gate security reviews before pilot and before any production path.

---

## Testing and Quality

### X-004: Known-answer fixture program

- Maintain reference fixtures for receipts, bundles, checkpoints, and proofs.

### X-005: End-to-end test matrix

- Track scenario coverage across replay, pilot, retrieval, and verification.

### X-006: Failure-path coverage

- Add tests for missing artifacts, broken publication, and invalid trust
  inputs.

---

## Operations

### X-007: Monitoring baseline

- Define health, readiness, publication-gap, and storage-failure monitoring.

### X-008: Backup and restore drills

- Run periodic recovery drills against representative export packages.

### X-009: Degraded-mode policy

- Document how the system behaves when signing, publication, or storage
  components fail.

### X-009A: Legal-hold and prompt-production policy

- Define how legal holds, prompt preservation, and export obligations are
  handled operationally.

---

## Documentation and Enablement

### X-010: Canonical terminology guide

- Keep product, engineering, and commercial language aligned across the suite.

### X-011: Pilot enablement pack

- Maintain materials needed for design-partner onboarding and evaluation.

### X-012: Reviewer guide

- Document how external reviewers interpret proof output and trust assumptions.

### X-012A: Communications and disclosure guide

- Document how audience scoping, redaction, and reviewed external exports are
  handled.

---

## Release Management

### X-013: Phase-gate checklist

- Define exit checklists for each roadmap phase.

### X-014: Versioning and compatibility policy

- Define compatibility rules for receipts, bundles, proofs, and verifier output.

### X-015: Change-log discipline

- Track changes that affect the proof contract or retained-evidence model.

---

## Commercial Readiness

### X-016: SOW and proof-boundary language

- Keep pilot and contract language aligned to the regulatory and technical docs.

### X-017: Integration decision template

- Standardize the memo used to justify any new expansion or integration path.

### X-018: Customer success criteria library

- Maintain reusable pilot and deployment success criteria by workflow type.

---

## Program Management

### X-019: Dependency and critical-path tracking

- Keep roadmap, master board, and ticket docs synchronized.

### X-020: Quarterly suite consistency review

- Review all docs and execution artifacts for terminology, scope, and roadmap
  alignment.
