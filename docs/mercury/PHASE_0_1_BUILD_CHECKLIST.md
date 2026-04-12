# MERCURY Phase 0-1 Build Checklist

**Date:** 2026-04-02  
**Audience:** product, engineering, and compliance leads

---

## 1. Working Assumption

Freeze this as the first supported workflow:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

Everything in Phase 0-1 should make that workflow real. Do not widen scope
until that loop works end to end.

---

## 2. Phase 0 Definition of Done

Phase 0 is complete when:

- the first workflow sentence is frozen across product, GTM, pilot, and
  engineering docs
- ARC reuse versus MERCURY net-new work is explicit
- `receipt.metadata.mercury` structure is frozen
- `Proof Package v1`, `Publication Profile v1`, and `Inquiry Package v1`
  contracts are defined at the document level
- the first pilot corpus and fixture plan are agreed

### Phase 0 Checklist

- [x] `P0-01` Freeze the exact first workflow sentence and pilot boundary.
- [x] `P0-02` Publish the ARC reuse memo for receipts, checkpoints, query,
      export, storage, CLI, and publication.
- [x] `P0-03` Freeze the MERCURY metadata namespace inside ARC receipts.
      Output:
      `business_ids`, `decision_context`, `chronology`, `provenance`,
      `sensitivity`, `disclosure`, and `approval_state`.
- [x] `P0-04` Freeze the evidence-bundle reference schema.
      Output:
      bundle manifest, artifact reference, retention class, legal-hold state,
      and redaction policy fields.
- [x] `P0-05` Freeze the query model for workflow, account, desk, strategy,
      release ID, rollback ID, exception ID, and inquiry ID.
- [x] `P0-06` Freeze `Proof Package v1` as a MERCURY wrapper over ARC evidence
      export rather than a replacement for it.
- [x] `P0-07` Freeze `Publication Profile v1` as the contract over ARC
      checkpoints, inclusion proofs, and witness or anchor expectations.
- [x] `P0-08` Freeze `Inquiry Package v1` as a reviewed export derived from a
      specific proof package plus disclosure and approval state.
- [x] `P0-09` Select and document the first demo and pilot corpus:
      propose -> approve -> release -> inquiry, with optional rollback.

---

## 3. Phase 1 Definition of Done

Phase 1 is complete when:

- MERCURY-specific receipt metadata is typed, serialized, and test-covered
- bundle manifests hash and verify deterministically
- business identifiers are queryable without raw JSON scans
- `Proof Package v1` can be exported from a fixture corpus
- a supported verifier command can validate the package end to end

### Phase 1 Checklist

- [x] `P1-01` Create `arc-mercury-core`.
      Output:
      typed evidence schemas and fixtures only; no API surface yet.
- [x] `P1-02` Implement typed MERCURY receipt metadata.
      Output:
      typed structs plus serialization into `ArcReceipt.metadata.mercury`.
- [x] `P1-03` Implement evidence-bundle manifest and hashing.
      Output:
      stable artifact references, manifest hashing, and known-answer tests.
- [x] `P1-04` Implement validation and canonical serialization helpers.
      Output:
      deterministic JSON fixtures and schema validation tests.
- [x] `P1-05` Extend SQLite persistence with extracted MERCURY index data.
      Output:
      indexed lookup for workflow, account, desk, strategy, release, rollback,
      exception, and inquiry identifiers.
- [x] `P1-06` Extend ARC receipt queries for MERCURY identifiers and approval
      state.
- [x] `P1-07` Implement `Proof Package v1` assembly on top of ARC evidence
      export.
      Output:
      wrapper manifest, package validator, and fixture package.
- [x] `P1-08` Implement an initial verifier command path.
      Output:
      verify, explain, and JSON result modes against the fixture package.
- [x] `P1-09` Produce the gold fixture workflow:
      propose -> approve -> release -> inquiry, plus one rollback variant.

---

## 4. Suggested Ownership

- **Engineer 1:** `arc-mercury-core` schemas, serialization, and fixtures
- **Engineer 2:** SQLite indexing and query extensions
- **Engineer 3:** proof package assembly and verifier command path
- **Product / compliance:** workflow sentence, proof boundary, inquiry policy,
  and pilot corpus

---

## 5. Recommended Build Order

Build in this exact order:

1. freeze the first workflow sentence
2. freeze the MERCURY metadata contract
3. build `arc-mercury-core`
4. add extracted SQLite indexes
5. extend query surfaces
6. wrap ARC evidence export into `Proof Package v1`
7. add verifier command path
8. generate the gold fixture package

If you change the order, you risk building a verifier with no stable object or
building query logic without the identifiers frozen.

---

## 6. Scope Discipline

Do not include these in Phase 0-1:

- live FIX
- OMS or EMS integration
- browser UI
- case-management connectors
- archive or surveillance connectors
- supervised-live deployment
- external witness service operation
- customer-specific dashboards

The only goal in Phase 0-1 is a stable proof chain for one governed workflow.
