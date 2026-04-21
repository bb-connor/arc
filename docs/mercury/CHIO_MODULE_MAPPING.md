# MERCURY Phase 0-1 Chio Module Mapping

**Date:** 2026-04-02  
**Audience:** engineering leads and implementers

---

## 1. Mapping Principles

MERCURY should reuse Chio's signed-evidence substrate instead of forking it.

Build rules:

1. Do not invent a new receipt envelope for Phase 0-1.
2. Do not invent a new checkpoint format for Phase 0-1.
3. Treat `Proof Package v1` as a MERCURY wrapper over Chio evidence export.
4. Keep MERCURY-specific semantics in typed metadata, bundle manifests, query
   extensions, and package contracts.
5. Do not build a new service or UI before the proof chain works locally.

---

## 2. Existing Chio Reuse

These capabilities already exist in Chio and should be reused directly.

| Need | Chio module(s) to reuse | Notes |
|------|-------------------------|-------|
| Signed receipt envelope | `crates/chio-core/src/receipt.rs` | `ChioReceipt` already has a signed body plus extensible `metadata` |
| Receipt signing path | `crates/chio-kernel/src/lib.rs` | Kernel already signs allow/deny/incomplete outcomes |
| Checkpoints and inclusion proofs | `crates/chio-kernel/src/checkpoint.rs` | Reuse `KernelCheckpoint` and `ReceiptInclusionProof` directly |
| Export bundle contract | `crates/chio-kernel/src/evidence_export.rs` | Current Chio export bundle is the right base object |
| Local evidence package assembly | `crates/chio-store-sqlite/src/evidence_export.rs` | Reuse the SQLite export path rather than rebuilding it |
| Receipt persistence | `crates/chio-store-sqlite/src/receipt_store.rs` | Existing store already persists raw signed receipts plus indexed fields |
| Query surface | `crates/chio-kernel/src/receipt_query.rs` and `crates/chio-store-sqlite/src/receipt_query.rs` | Extend these instead of creating a separate query stack |
| Generic evidence export substrate | `crates/chio-control-plane/src/lib.rs` and `crates/chio-cli/src/evidence_export.rs` | Reuse Chio's generic export helpers; keep the MERCURY operator surface separate |
| Kernel wiring and local control-plane config | `crates/chio-control-plane/src/lib.rs` | Reuse kernel and store configuration flows |
| Publication and witness tooling | `crates/chio-anchor` | Needed for later `Publication Profile v1` implementation, not for first code written |

---

## 3. Net-New MERCURY Code

Phase 0-1 still needs a MERCURY-specific typed layer.

### Recommended new crate

Create:

`crates/chio-mercury-core`

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

Do **not** hide MERCURY inside `chio-cli`.

Fastest credible path after the boundary correction:

1. keep MERCURY package validation logic in `chio-mercury-core`
2. reuse Chio's generic evidence-export helpers from `chio-control-plane`
3. expose the operator-facing command through the dedicated `chio-mercury` app

---

## 4. Ticket-to-Module Mapping

| Checklist item | Reuse directly | Extend | Net-new code |
|----------------|----------------|--------|--------------|
| `P0-02` Chio reuse memo | `chio-core`, `chio-kernel`, `chio-store-sqlite`, `chio-control-plane`, `chio-anchor` | none | document only |
| `P0-03` MERCURY metadata namespace | `ChioReceipt.metadata` in `crates/chio-core/src/receipt.rs` | kernel receipt construction only if helper wiring is needed | `chio-mercury-core::receipt_metadata` |
| `P0-04` evidence-bundle schema | Chio export bundle as reference | none initially | `chio-mercury-core::bundle` |
| `P0-05` query model | `ReceiptQuery` and SQLite query flow | `crates/chio-kernel/src/receipt_query.rs`, `crates/chio-store-sqlite/src/receipt_query.rs` | `chio-mercury-core::query` |
| `P0-06` `Proof Package v1` | `EvidenceExportBundle` and generic manifest flow | `crates/chio-control-plane/src/lib.rs` and `crates/chio-cli/src/evidence_export.rs` | `chio-mercury-core::proof_package` |
| `P0-07` `Publication Profile v1` | checkpoints and anchor tooling | later in `chio-anchor` and export manifest code | profile struct and docs in `chio-mercury-core` |
| `P0-08` `Inquiry Package v1` | underlying proof package and redaction metadata | later CLI export path | `chio-mercury-core::inquiry_package` |
| `P1-02` typed metadata serialization | Chio receipt envelope | append path if helper added | `chio-mercury-core::receipt_metadata` |
| `P1-03` bundle hashing | Chio canonical JSON helpers | none | `chio-mercury-core::bundle` |
| `P1-05` extracted SQLite indexes | existing `chio_tool_receipts` persistence | `crates/chio-store-sqlite/src/receipt_store.rs` | MERCURY-specific index table or extracted columns |
| `P1-06` business-ID queries | existing query surface | `crates/chio-kernel/src/receipt_query.rs`, `crates/chio-store-sqlite/src/receipt_query.rs` | MERCURY filter types |
| `P1-07` package assembly | Chio evidence export bundle and manifest verification | `crates/chio-control-plane/src/lib.rs` and `crates/chio-cli/src/evidence_export.rs` | MERCURY package adapter |
| `P1-08` verifier command | Chio evidence package validation path | `crates/chio-mercury/src/main.rs`, `crates/chio-mercury/src/commands.rs`, and `crates/chio-cli/src/evidence_export.rs` | thin MERCURY app wrapper |

---

## 5. Exact First Build Order

If the goal is to start coding immediately, build in this order.

### Step 1

Create `crates/chio-mercury-core` with typed metadata only.

Reason:

- it freezes the object model before storage or query work starts

### Step 2

Define `receipt.metadata.mercury` and a fixture receipt.

Reason:

- Chio already signs receipts with arbitrary metadata, so this is the lowest-risk
  integration point

### Step 3

Add extracted MERCURY index storage in `chio-store-sqlite`.

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

Wrap Chio evidence export into `Proof Package v1`.

Reason:

- Chio already exports receipts, checkpoints, lineage, inclusion proofs, and
  retention metadata
- MERCURY should add meaning and packaging, not replace the substrate

### Step 6

Add a first verifier command in `chio-mercury`.

Reason:

- this gives immediate operator value without widening Chio's generic shell

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

- `crates/chio-a2a-adapter`
- `crates/chio-hosted-mcp`
- `crates/chio-siem`
- `crates/chio-settle`
- `crates/chio-web3-bindings`
- partner-specific connectors
- browser-facing UI layers

The only publication-related exception is that `chio-anchor` is the correct
place to extend witness or immutable-publication behavior later, once
`Publication Profile v1` leaves document-only status.
