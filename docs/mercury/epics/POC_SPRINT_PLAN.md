# MERCURY Pilot Sprint Plan

**Duration:** 45 calendar days  
**Linked docs:** [../POC_DESIGN.md](../POC_DESIGN.md), [MASTER_PROJECT.md](MASTER_PROJECT.md)

---

## Sprint 0: Scoping and Access

**Goal:** Freeze the workflow, success criteria, and source inputs.

Linked tickets:

- T-010 workflow selection template
- T-011 proof-boundary statement
- T-012 pilot data and retention profile
- T-012A first workflow selection pack

Exit criteria:

- workflow owner identified
- source inputs approved
- pilot success criteria agreed

---

## Sprint 1: First Evidence Chain

**Goal:** Produce the first signed receipts and checkpoints for the selected
release, rollback, exception, approval, or inquiry workflow.

Linked tickets:

- T-101 ingestion adapter contract
- T-102 event normalization pipeline
- T-013 core crate scaffold
- T-022 verifier library surface

Exit criteria:

- first end-to-end signed receipt generated
- checkpoint flow confirmed

---

## Sprint 2: Artifact Retention and Queries

**Goal:** Make the evidence useful for investigation.

Linked tickets:

- T-016 bundle manifest type
- T-017 bundle hashing
- T-019 business identifier filters
- T-110 artifact retention service
- T-113 source ID reconciliation model
- T-112A record taxonomy and communications policy

Exit criteria:

- source artifacts retained or referenced correctly
- investigator can retrieve evidence by business identifiers

---

## Sprint 3: Verification and Retrieval

**Goal:** Expose `Proof Package v1` and related proof material in a clean
retrieval path.

Linked tickets:

- T-023 CLI commands and output
- T-116 receipt retrieval endpoint
- T-117 checkpoint and proof endpoints
- T-118 evidence bundle retrieval endpoint
- T-118A `Proof Package v1` export endpoint
- T-118B `Inquiry Package v1` export endpoint

Exit criteria:

- external reviewer can retrieve and verify a pilot record through
  `Proof Package v1`
- reviewed inquiry export can be generated from the same record

---

## Sprint 4: Publication and Operational Readiness

**Goal:** Make the pilot externally supportable.

Linked tickets:

- T-122 checkpoint publication pipeline
- T-123 external witness integration
- T-125 key onboarding runbook
- T-126 deployment runbook

Exit criteria:

- publication path operational
- runbooks complete enough for pilot execution

---

## Sprint 5: Pilot Run and Readout

**Goal:** Execute the pilot workflow and package the commercial decision.

Linked tickets:

- T-115 pilot walkthrough dataset
- T-128 pilot report template
- T-129 conversion decision memo
- T-130 pilot acceptance checklist

Exit criteria:

- pilot report delivered
- next-step decision documented

---

## Pilot Success Standard

The sprint plan is complete when:

- the workflow evidence is verifiable end-to-end
- the evidence is useful to the design partner
- the post-pilot recommendation is specific enough to fund or decline cleanly
