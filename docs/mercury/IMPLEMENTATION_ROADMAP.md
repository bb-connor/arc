# MERCURY Product Roadmap

**Version:** 1.0  
**Date:** 2026-04-03  
**Audience:** Engineering, product, and design-partner stakeholders

---

## 1. Program Summary

MERCURY is being built in two layers:

- **Phases 0-3:** product program through pilot readiness
- **Post-pilot bridge:** supervised-live productionization for the same workflow
- **Phases 4-5:** broader expansion programs unlocked after pilot validation

The initial product goal is straightforward:

1. generate signed decision-evidence records for a defined workflow
2. retain the supporting evidence needed to reconstruct that record later
3. publish the proof material needed for independent verification
4. run a design-partner pilot that proves review and investigation value for
   one release, rollback, exception, or inquiry workflow

The exact first workflow sentence is frozen as:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

### Team assumption

- 3 senior Rust engineers full-time
- part-time product and compliance support
- no assumption of a dedicated frontend team in the initial program

---

## 2. Build Principles

1. Reuse ARC's receipt, signing, and verification substrate wherever possible.
2. Make evidence fidelity and proof distribution more important than UI breadth.
3. Capture raw source artifacts and reconciliation metadata, not just derived
   adapter output.
4. Support one funded productionization, expansion, or integration path at a
   time.
5. Keep proof boundaries explicit in both engineering and commercial docs.

---

## 3. Phases 0-3: Current Product Program

### Phase 0: Scope Lock and Reuse Map (Weeks 1-4)

**Objective:** Establish the product boundary, reuse plan, and pilot topology.

Freeze this exact workflow sentence across product, GTM, pilot, and engineering
docs:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

**Deliverables**

- ARC reuse and gap inventory
- ARC-to-MERCURY portfolio map and commercial boundary
- MERCURY kernel profile assumptions
- canonical evidence object definition
- `Proof Package v1` and `Publication Profile v1` definitions
- `Inquiry Package v1` definition
- design-partner pilot topology and proof boundary

**Exit criteria**

- one product definition is accepted across docs
- one pilot definition is accepted across docs
- reuse vs. net-new work is explicit

### Phase 1: Core Evidence and Verification (Weeks 5-8)

**Objective:** Build the trading-specific evidence model and one strong
verification surface.

**Deliverables**

- `arc-mercury-core`
- receipt metadata, chronology and causality fields, and evidence-bundle schema
- provider and dependency provenance fields
- sensitivity, disclosure, and export-policy fields
- query extensions for business identifiers
- MERCURY verification through the dedicated `arc-mercury` app, backed by
  `arc-mercury-core` and ARC's generic evidence-export substrate

**Exit criteria**

- receipts verify end-to-end
- evidence bundles hash and verify correctly
- queries support pilot-scale investigation flows
- the first supported verifier command in `arc-mercury` validates the package
  contract end to end

### Phase 2: Pilot Evidence Stack (Weeks 9-16)

**Objective:** Deliver an end-to-end stack for replay, shadow, synthetic, or
paper-trading workflows centered on one governed AI change path.

**Deliverables**

- replay / shadow ingestion path
- deterministic simulated workflow harness
- change-control, release, rollback, and approval capture
- raw artifact retention and reconciliation metadata
- record taxonomy, legal-hold, and export-policy handling
- end-to-end pilot harness

**Exit criteria**

- a complete workflow can generate receipts, checkpoints, and evidence bundles
- retained source identifiers survive retrieval and verification
- the stack supports at least one credible buyer story without requiring live
  FIX or OMS certification

### Phase 3: Pilot Readiness and Proof Distribution (Weeks 17-24)

**Objective:** Make the system ready for external design-partner use.

**Deliverables**

- minimal proof-package API serving `Proof Package v1`
- `Inquiry Package v1` generation and retrieval
- entitlement scoping by client, account, or desk
- checkpoint publication with an external witness or immutable publication step
- normative publication semantics for continuity, completeness, and freshness
- key, deployment, monitoring, and degraded-mode runbooks
- pilot report template and conversion package

**Exit criteria**

- a design partner can retrieve and independently verify receipts and proofs
- a design partner can generate and review inquiry packages safely
- checkpoint publication does not rely only on operator-controlled storage
- deployment and key management are documented well enough for external pilot
  review

---

## 4. Post-Pilot Bridge

Before MERCURY broadens into multiple expansion tracks, the preferred next step
is to productionize the same governed workflow in supervised-live form.

### Bridge objective

- prove the same evidence model survives real operational use
- confirm rollout, rollback, and inquiry handling in controlled production
- avoid jumping into multiple connectors before the first workflow is sticky
- keep existing customer execution systems primary while MERCURY remains the
  evidence layer around the workflow
- close the bridge with one explicit proceed, defer, or stop artifact

### Bridge gate

- one pilot converts
- workflow ownership and outage handling are explicit
- the buyer wants the same workflow in supervised-live production
- the operating model and decision record are accepted as the close-out shape

---

## 5. Phases 4-5: Expansion Tracks

These phases are part of the roadmap, but they start only after phases 0-3
produce a successful pilot outcome and a clear funded next step.

### Phase 4: Governance, Downstream Consumers, and Assurance

**Tracks**

- Governance Workbench
  Approval, release, rollback, exception, and model or policy change-review
  workflows built on the same evidence and publication model.
- Downstream Consumer Integrations
  Archive, review, surveillance, and case-management distribution that reuses
  the same proof and inquiry package contracts.
- Assurance Suite
  Reviewer-facing packages, investigation views, and export surfaces for
  internal, auditor, and counterparty review.

**Current activated path**

- one assurance-suite lane over the existing proof, inquiry, reviewer,
  qualification, and governance-decision artifacts
- one bounded reviewer-population set for internal, auditor, and counterparty
  review
- one disclosure-profile, review-package, and investigation-package family
  rooted in the existing Mercury proof chain

**Gate to start**

- one pilot converts
- supervised-live productionization is either operating or intentionally
  deferred
- one specific governance, downstream, or assurance path is commercially
  justified
- ownership for review, export, and support obligations is defined

### Phase 5: Embedded OEM, Trust Network, and ARC-Wall

**Tracks**

- Embedded OEM Distribution
  True partner or OEM packaging once downstream consumption and proof contracts
  have already been validated.
- Trust Network
  Shared publication, witness, trust-anchor, and interoperability services that
  make proof distribution easier across firms and reviewers.
- ARC-Wall
  Information-domain control evidence and companion product packaging using the
  same trust and publication foundations.

**Current activated path**

- one ARC-Wall companion-product lane over ARC guard, receipt, checkpoint,
  publication, and verification truth
- one buyer motion: `control_room_barrier_review`
- one control surface: `tool_access_domain_boundary`
- one source/protected domain pair: `research -> execution`
- one explicit owner boundary: `barrier-control-room` plus `arc-wall-ops`

**Gate to start**

- the core evidence platform is stable
- at least one phase 4 expansion track is operating credibly
- trust-network or ARC-Wall work has a clear buyer or ecosystem sponsor

---

## 6. Post-Phase 5: Multi-Product Platform Hardening

Once one ARC-Wall lane is validated, the next bounded step is not another
buyer motion. It is one hardening lane over the current product set.

### Current activated path

- one shared ARC service catalog across MERCURY and ARC-Wall
- one cross-product governance model for release, incident, and trust material
- one bounded platform-hardening backlog for sustained multi-product operation

### Gate to start

- MERCURY and ARC-Wall each have one validated lane on the same ARC substrate
- product owners agree that shared-service boundaries must stay explicit
- the next funded work is hardening, not a new buyer or connector lane

---

## 7. Milestones

| Milestone | Week | Meaning |
|----------|------|---------|
| M0: Scope locked | 2 | Canonical product and pilot definitions are fixed |
| M1: Proof chain working | 8 | Receipts, bundles, checkpoints, and CLI verification work end-to-end |
| M2: Pilot stack working | 16 | Full replay/shadow workflow runs successfully |
| M3: Pilot ready | 24 | External design-partner deployment is supportable |
| M3.5: First supervised-live decision | Post-pilot | The same workflow either moves into supervised-live production or is intentionally deferred |
| M4: First expansion-track decision | Post-pilot | One specific governance, downstream, assurance, OEM, trust, or ARC-Wall path is funded |
| M5: Platform expansion | Post-M4 | Expansion tracks begin in a sequenced way |

---

## 8. Release Criteria

The initial product release is complete when:

1. a workflow run produces signed receipts and retrievable evidence bundles for
   one governed change or inquiry workflow
2. those records can be independently verified using a supported verifier and
   `Proof Package v1`
3. reviewed inquiry exports can be generated safely from the same underlying
   proof
4. reviewers can query and reconstruct a workflow using business identifiers
5. publication, key distribution, and operational procedures are documented for
   external pilot use

The initial release does not require:

- a homegrown FIX engine
- simultaneous support for multiple OMS/EMS platforms
- a browser portal
- multi-language SDK parity
- production-grade market-data attestation
- compliance dashboards

---

## 8. Key Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Integration sprawl | Product program gets consumed by bespoke connectors | Only start one funded productionization, expansion, or integration path at a time |
| Category absorption | Archive, surveillance, or OEMS vendors subsume the visible surface | Keep the wedge workflow-native and proof-native, not generic governance |
| Weak proof distribution | Buyers discount independence claims | Add external witness or immutable publication before pilot close |
| Missing source artifacts | Evidence is technically valid but operationally useless | Make artifact retention and reconciliation mandatory in pilot flows |
| Commercial overclaim | Legal or compliance teams lose trust | Keep product and regulatory language aligned to the proof boundary |
| Ops treated as polish | Week 24 yields a demo, not a pilot | Make runbooks, keys, and degraded mode exit criteria |

---

## 9. Program View

The program is designed to produce a commercially credible product quickly,
then expand only where buyers create clear pull. That sequencing protects both
engineering focus and product credibility.
