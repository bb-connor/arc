# MERCURY Phase 0-1 ARC Module Mapping

**Date:** 2026-04-02  
**Audience:** engineering leads and implementers

---

## 1. Mapping Principles

MERCURY should reuse ARC's signed-evidence substrate instead of forking it.

Build rules:

1. Do not invent a new receipt envelope for Phase 0-1.
2. Do not invent a new checkpoint format for Phase 0-1.
3. Treat `Proof Package v1` as a MERCURY wrapper over ARC evidence export.
4. Keep MERCURY-specific semantics in typed metadata, bundle manifests, query
   extensions, and package contracts.
5. Do not build a new service or UI before the proof chain works locally.

---

## 2. Existing ARC Reuse

These capabilities already exist in ARC and should be reused directly.

| Need | ARC module(s) to reuse | Notes |
|------|-------------------------|-------|
| Signed receipt envelope | `crates/arc-core/src/receipt.rs` | `ArcReceipt` already has a signed body plus extensible `metadata` |
| Receipt signing path | `crates/arc-kernel/src/lib.rs` | Kernel already signs allow/deny/incomplete outcomes |
| Checkpoints and inclusion proofs | `crates/arc-kernel/src/checkpoint.rs` | Reuse `KernelCheckpoint` and `ReceiptInclusionProof` directly |
| Export bundle contract | `crates/arc-kernel/src/evidence_export.rs` | Current ARC export bundle is the right base object |
| Local evidence package assembly | `crates/arc-store-sqlite/src/evidence_export.rs` | Reuse the SQLite export path rather than rebuilding it |
| Receipt persistence | `crates/arc-store-sqlite/src/receipt_store.rs` | Existing store already persists raw signed receipts plus indexed fields |
| Query surface | `crates/arc-kernel/src/receipt_query.rs` and `crates/arc-store-sqlite/src/receipt_query.rs` | Extend these instead of creating a separate query stack |
| Generic evidence export substrate | `crates/arc-control-plane/src/lib.rs` and `crates/arc-cli/src/evidence_export.rs` | Reuse ARC's generic export helpers; keep the MERCURY operator surface separate |
| Kernel wiring and local control-plane config | `crates/arc-control-plane/src/lib.rs` | Reuse kernel and store configuration flows |
| Publication and witness tooling | `crates/arc-anchor` | Needed for later `Publication Profile v1` implementation, not for first code written |

---

## 3. Net-New MERCURY Code

Phase 0-1 still needs a MERCURY-specific typed layer.

### Recommended new crate

Create:

`crates/arc-mercury-core`

Recommended initial module layout:

- `src/receipt_metadata.rs`
- `src/bundle.rs`
- `src/query.rs`
- `src/proof_package.rs`
- `src/inquiry_package.rs`
- `src/fixtures.rs`

What belongs there:

- typed MERCURY receipt metadata
- business identifier types
- chronology and causality fields
- provider and dependency provenance fields
- sensitivity, disclosure, and redaction policy fields
- evidence-bundle manifest types
- `ProofPackageV1` and `InquiryPackageV1` wrapper types

What does **not** belong there yet:

- HTTP API
- browser UI
- live broker connectivity
- partner connectors

### Verifier path recommendation

Do **not** hide MERCURY inside `arc-cli`.

Fastest credible path after the boundary correction:

1. keep MERCURY package validation logic in `arc-mercury-core`
2. reuse ARC's generic evidence-export helpers from `arc-control-plane`
3. expose the operator-facing command through the dedicated `arc-mercury` app

---

## 4. Ticket-to-Module Mapping

| Checklist item | Reuse directly | Extend | Net-new code |
|----------------|----------------|--------|--------------|
| `P0-02` ARC reuse memo | `arc-core`, `arc-kernel`, `arc-store-sqlite`, `arc-control-plane`, `arc-anchor` | none | document only |
| `P0-03` MERCURY metadata namespace | `ArcReceipt.metadata` in `crates/arc-core/src/receipt.rs` | kernel receipt construction only if helper wiring is needed | `arc-mercury-core::receipt_metadata` |
| `P0-04` evidence-bundle schema | ARC export bundle as reference | none initially | `arc-mercury-core::bundle` |
| `P0-05` query model | `ReceiptQuery` and SQLite query flow | `crates/arc-kernel/src/receipt_query.rs`, `crates/arc-store-sqlite/src/receipt_query.rs` | `arc-mercury-core::query` |
| `P0-06` `Proof Package v1` | `EvidenceExportBundle` and generic manifest flow | `crates/arc-control-plane/src/lib.rs` and `crates/arc-cli/src/evidence_export.rs` | `arc-mercury-core::proof_package` |
| `P0-07` `Publication Profile v1` | checkpoints and anchor tooling | later in `arc-anchor` and export manifest code | profile struct and docs in `arc-mercury-core` |
| `P0-08` `Inquiry Package v1` | underlying proof package and redaction metadata | later CLI export path | `arc-mercury-core::inquiry_package` |
| `P1-02` typed metadata serialization | ARC receipt envelope | append path if helper added | `arc-mercury-core::receipt_metadata` |
| `P1-03` bundle hashing | ARC canonical JSON helpers | none | `arc-mercury-core::bundle` |
| `P1-05` extracted SQLite indexes | existing `arc_tool_receipts` persistence | `crates/arc-store-sqlite/src/receipt_store.rs` | MERCURY-specific index table or extracted columns |
| `P1-06` business-ID queries | existing query surface | `crates/arc-kernel/src/receipt_query.rs`, `crates/arc-store-sqlite/src/receipt_query.rs` | MERCURY filter types |
| `P1-07` package assembly | ARC evidence export bundle and manifest verification | `crates/arc-control-plane/src/lib.rs` and `crates/arc-cli/src/evidence_export.rs` | MERCURY package adapter |
| `P1-08` verifier command | ARC evidence package validation path | `crates/arc-mercury/src/main.rs`, `crates/arc-mercury/src/commands.rs`, and `crates/arc-cli/src/evidence_export.rs` | thin MERCURY app wrapper |

---

## 5. Exact First Build Order

If the goal is to start coding immediately, build in this order.

### Step 1

Create `crates/arc-mercury-core` with typed metadata only.

Reason:

- it freezes the object model before storage or query work starts

### Step 2

Define `receipt.metadata.mercury` and a fixture receipt.

Reason:

- ARC already signs receipts with arbitrary metadata, so this is the lowest-risk
  integration point

### Step 3

Add extracted MERCURY index storage in `arc-store-sqlite`.

Recommended approach:

- add dedicated extracted columns or a side index table keyed by `receipt_id`
- do **not** rely on JSON scans over `raw_json` for production query paths

### Step 4

Extend `ReceiptQuery` and SQLite query execution for business identifiers and
approval state.

Reason:

- the first pilot needs retrieval by workflow and review identifiers, not only
  capability or agent subject

### Step 5

Wrap ARC evidence export into `Proof Package v1`.

Reason:

- ARC already exports receipts, checkpoints, lineage, inclusion proofs, and
  retention metadata
- MERCURY should add meaning and packaging, not replace the substrate

### Step 6

Add a first verifier command in `arc-mercury`.

Reason:

- this gives immediate operator value without widening ARC's generic shell

### Step 7

Generate one gold package for:

- proposal
- approval
- release
- inquiry
- rollback variant

Reason:

- docs, demo, verifier, and pilot all need the same fixture corpus

---

## 6. Modules To Leave Alone For Now

These are not Phase 0-1 priorities:

- `crates/arc-a2a-adapter`
- `crates/arc-hosted-mcp`
- `crates/arc-siem`
- `crates/arc-settle`
- `crates/arc-web3-bindings`
- partner-specific connectors
- browser-facing UI layers

The only publication-related exception is that `arc-anchor` is the correct
place to extend witness or immutable-publication behavior later, once
`Publication Profile v1` leaves document-only status.
