# MERCURY Master Project Board

**Version:** 1.0  
**Date:** 2026-04-02  
**Source of truth:** [../IMPLEMENTATION_ROADMAP.md](../IMPLEMENTATION_ROADMAP.md)

---

## 1. Project Overview

MERCURY is organized into six phases plus a post-pilot bridge:

- phases 0-3: product program through pilot readiness
- post-pilot bridge: first supervised-live productionization
- phases 4-5: broader expansion programs activated after pilot validation

The active objective is to deliver a design-partner-ready evidence platform
with signed receipts, retained source artifacts, proof publication, inquiry
packaging, and one supported verifier surface.

---

## 2. Phase Summary

| Phase | Title | Weeks | Epics | Outcome |
|------|-------|-------|-------|---------|
| 0 | Scope Lock and Reuse Map | 1-4 | 4 | Canonical scope, reuse plan, pilot definition |
| 1 | Core Evidence and Verification | 5-8 | 5 | Evidence model, proof package, verifier, query foundations |
| 2 | Pilot Evidence Stack | 9-16 | 6 | Replay/shadow ingestion, artifact retention, record policy, end-to-end harness |
| 3 | Pilot Readiness and Proof Distribution | 17-24 | 5 | Proof Package API, inquiry package, entitlements, publication, runbooks, pilot package |
| 3.5 | Supervised-Live Productionization | Contingent | 1 | The first governed workflow moves into controlled production |
| 4 | Governance, Downstream Consumers, and Assurance | Contingent | 3 | Governed workflows, connectors, and reviewer-facing products |
| 5 | Embedded OEM, Trust Network, and Chio-Wall | Contingent | 4 | Partner packaging, shared trust services, and companion-product foundations |

**Total epics:** 28

---

## 3. Epic Registry

### Phase 0

#### E-001: Chio Reuse Inventory

- Map Chio components reused for receipts, signing, storage, and verification.

#### E-002: Canonical Evidence Object

- Define MERCURY-specific metadata, chronology and causality fields,
  evidence-bundle references, disclosure policy fields, and business
  identifiers.

#### E-003: Kernel Profile and Trust Assumptions

- Document pilot-oriented signing, storage, and trust assumptions.

#### E-004: Pilot Topology Definition

- Freeze the workflow shape, data sources, and proof boundary for the first
  design-partner motion.

### Phase 1

#### E-005: `chio-mercury-core`

- Build trading-specific evidence types on top of Chio.

#### E-006: Evidence Bundle Schema

- Define bundle hashing, retention references, and integrity checks.

#### E-007: Query Extensions

- Support account, desk, workflow, order, strategy, and decision-type lookup.

#### E-008: Verifier Library and CLI

- Ship one supported verifier surface for the initial product.

#### E-008A: Proof Package and Publication Profile

- Freeze the canonical export package and publication semantics used across the
  product.

### Phase 2

#### E-009: Replay / Shadow Ingestion

- Ingest replayed, synthetic, or paper-trading workflow events.

#### E-010: Simulated Workflow Harness

- Provide deterministic pilot runs and demo datasets.

#### E-011: Change-Control and Supervisory Attestation

- Capture release, rollback, approval, denial, and supervisory checks as
  evidence objects.

#### E-012: Raw Artifact Retention

- Retain source artifacts instead of only derived adapter output.

#### E-013: Reconciliation and End-to-End Harness

- Tie source-system identifiers to the end-to-end proof chain.

#### E-013A: Record Taxonomy and Export Policy

- Define record classes, legal-hold behavior, and export or disclosure rules
  for retained evidence.

### Phase 3

#### E-014: Proof Package API

- Serve receipts, checkpoints, proofs, evidence bundles, and `Proof Package v1`
  exports.

#### E-015: Entitlement Model

- Scope access by business identity, not only by agent subject.

#### E-016: Publication and External Witness

- Add checkpoint publication that supports independent review.

#### E-017: Deployment and Key Runbooks

- Document deployment, monitoring, rotation, backup, and degraded mode.

#### E-018: Pilot Exit Package

- Standardize the pilot report, conversion criteria, and next-step memo.

### Post-Pilot Bridge

#### E-018A: First Supervised-Live Productionization

- Move the same governed workflow from replay or shadow into controlled
  production before broad expansion.

### Phase 4

#### E-020: Governance Workbench

- Add governed approval, release, rollback, exception, and change-review
  workflows.

#### E-021: Downstream Consumer Integrations

- Add archive, review, surveillance, and case-management connectors that reuse
  the same proof and inquiry package contracts.

#### E-022: Assurance Suite

- Add reviewer-facing assurance packages and export surfaces for external and
  internal review.

### Phase 5

#### E-023: Embedded OEM Distribution

- Package MERCURY for true OEM or partner embedding once downstream
  consumption is validated.

#### E-024: Trust Network

- Add shared publication, witness, trust-anchor, and interoperability services.

#### E-025: Chio-Wall Core and Buyer Motion

- Build the companion information-domain control product on shared Chio
  foundations.

#### E-026: Platform Hardening for Multi-Product Operation

- Support shared services, governance, and operational boundaries across
  MERCURY extensions.

---

## 4. Dependency Graph

```text
E-001 -> E-002 -> E-005 -> E-009 -> E-014
E-003 -> E-005
E-004 -> E-009
E-005 -> E-006 -> E-008 -> E-014
E-005 -> E-007 -> E-014
E-002 -> E-008A -> E-014
E-003 -> E-008A
E-009 -> E-010 -> E-013
E-009 -> E-011 -> E-013
E-009 -> E-012 -> E-013 -> E-013A -> E-014
E-014 -> E-016
E-014 -> E-017
E-014 -> E-018
E-014 -> E-015
E-018 -> E-018A
E-018A -> E-020
E-018 -> E-021
E-018 -> E-022
E-021 -> E-023
E-022 -> E-023
E-023 -> E-024
E-024 -> E-025
E-025 -> E-026
```

---

## 5. Active Critical Path

1. scope lock and canonical evidence object
2. verifier-capable core evidence model
3. replay / shadow pilot stack
4. proof package, inquiry package, API, and publication
5. operational readiness for an external pilot
6. productionize the same workflow before broad expansion

---

## 6. Milestone Markers

| Marker | Meaning |
|--------|---------|
| M0 | scope and pilot topology fixed |
| M1 | proof chain works end-to-end |
| M2 | replay / shadow pilot stack works end-to-end |
| M3 | design-partner pilot is supportable |
| M3.5 | first supervised-live productionization decision made |
| M4 | first expansion-track path selected |
| M5 | trust-network or companion-product program begins |

---

## 7. Success Conditions

The product program succeeds when:

- a design partner can verify workflow evidence independently
- the evidence improves review or investigation quality materially
- the pilot yields a funded next step that is narrow enough to execute
- MERCURY proves sticky in one workflow before broad connector sprawl begins

That outcome creates the basis for the production and ecosystem phases that
follow.
