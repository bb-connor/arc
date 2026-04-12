# MERCURY Design-Partner Pilot

**Date:** 2026-04-03  
**Duration:** 45 calendar days

---

## 1. Pilot Objectives

The pilot is designed to answer five questions:

1. Can MERCURY produce signed evidence for one controlled model, prompt,
   policy, or parameter release or rollback workflow?
2. Can a design partner retrieve and independently verify that evidence?
3. Do retained source artifacts materially improve review or investigation
   quality?
4. What source-system inputs must be retained for the evidence to be credible?
5. Should the same workflow proceed to supervised-live, stay deferred, or
   stop after the pilot?

---

## 2. Pilot Scope

The exact first workflow sentence is frozen as:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

### In scope

| Component | Notes |
|-----------|-------|
| Replay, synthetic, shadow, or paper-trading workflow | One supervised workflow only |
| Signed receipts and checkpoints | Real signing and proof chain |
| Evidence bundles | Retained artifacts referenced by receipts |
| Proof Package v1 + retrieval surface | Receipts, proofs, checkpoints, witness material, bundles |
| Inquiry Package v1 | Reviewed export for internal or external inquiry use |
| CLI verifier | One supported independent verifier |
| Reconciliation metadata | Source-system IDs, chronology, evidence status, and release lineage |
| Pilot report | Standardized readout and conversion memo |
| Supervised-live bridge inputs | Operating model and proceed/defer/stop decision template for the same workflow |

### Out of scope

| Component | Reason |
|-----------|--------|
| Multi-workflow deployment | Not needed to validate value |
| Homegrown FIX engine | Outside the pilot objective |
| Simultaneous multi-platform OMS support | Too much integration surface for a first pilot |
| Browser portal and SDK parity | Verification UX breadth is not the first constraint |
| Best-execution or regulatory claims | Outside the product proof boundary |
| ARC-Wall | Separate expansion track |

---

## 3. Pilot Architecture

```text
Workflow events or replay feed
        ->
MERCURY pilot adapter
        ->
Signed receipt + evidence bundle reference + chronology metadata
        ->
Checkpoint publication
        ->
Proof Package v1 + Inquiry Package v1 + verifier CLI
```

Key design choices:

- evidence quality over workflow breadth
- raw source artifacts retained where practical
- proof publication suitable for external review
- business identifiers available for retrieval and investigation
- one measurable operational improvement in a governed change or inquiry
  workflow

---

## 4. Deliverables

### Software deliverables

- pilot adapter and ingestion path
- verifier CLI
- Proof Package v1, Inquiry Package v1, and retrieval surface
- sample evidence dataset

### Documentation deliverables

- deployment guide
- key and trust-onboarding guide
- pilot evidence report
- supervised-live operating model
- supervised-live qualification package
- supervised-live decision record

---

## 5. Pilot Plan

### Week 0: scoping

- choose the workflow
- choose the governed event that matters most: release, rollback, exception, or
  approval
- confirm source events and retention constraints
- define success criteria and named stakeholders

### Week 1: first evidence chain

- map workflow events to receipt structures
- map release, rollback, approval, and exception chronology into the evidence
  graph
- generate first signed records
- confirm checkpoint generation

### Week 2: artifact retention and queries

- retain source artifacts
- bind them to receipts
- enable lookup by business identifiers and chronology

### Week 3: verification

- expose Proof Package v1 retrieval
- expose Inquiry Package v1 generation
- run the verifier end-to-end
- confirm trust-distribution and publication flow

### Week 4: pilot run

- execute the agreed pilot workflow
- collect evidence quality and review-workflow feedback

### Week 5-6: readout and decision

- deliver pilot report
- generate the supervised-live qualification package
- review the supervised-live operating assumptions
- close one proceed/defer/stop decision record for the same workflow

---

## 6. Success Criteria

The pilot succeeds if:

1. a full workflow produces signed receipts, checkpoints, retrievable evidence
   bundles, Proof Package v1 exports, and Inquiry Package v1 exports
2. the design partner can verify the record independently
3. the evidence materially improves one release, rollback, exception, or
   inquiry workflow
4. the pilot yields one clear proceed/defer/stop decision record for the same
   workflow

Stretch criteria:

- pilot-scale run of 100,000+ events
- one retained artifact class beyond simple JSON payloads
- integration of the inquiry package into an existing review, archive, or
  surveillance workflow

---

## 7. Resourcing

### MERCURY team

- 2-3 engineers
- product / compliance support
- founder participation in readout

### Design partner

- workflow owner
- compliance or risk reviewer
- infrastructure contact
- access to source events or approved equivalents

---

## 8. Pilot Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Scope expands mid-pilot | schedule slips and evidence quality drops | freeze one workflow and one success criterion up front |
| Source artifacts cannot be retained | evidence becomes weak for investigation | agree retention policy during scoping |
| Proof publication stays entirely operator-controlled | independence claim is weak | require external witness in the pilot package |
| Buyer expects economic execution proof | pilot gets evaluated against the wrong outcome | state the proof boundary in the SOW and readout |

---

## 9. Conversion Paths

### Outcome A: annual evidence platform

The workflow benefits from ongoing deployment in shadow-mode or supervised use.

### Outcome B: supervised-live productionization

The same workflow moves into a controlled supervised-live deployment under the
frozen bridge, qualification package, and operating model.

### Outcome C: one deeper distribution or expansion path

Only after the supervised-live bridge is explicitly deferred or closed, the
buyer may fund one specific next step such as:

- one assurance or governance workflow
- one archive, review, or surveillance connector
- one later OMS/EMS or FIX path

The first downstream case-management review lane is now complete. The current
selected next step in the repo is one assurance-suite reviewer family for
`internal_review`, `auditor_review`, and `counterparty_review`, rooted in the
same proof, qualification, and governance artifacts rather than a broad
governance or connector portfolio.

### Outcome D: no-go

The evidence does not justify product deployment or the account only wants
services. That is a valid outcome and useful product learning.
