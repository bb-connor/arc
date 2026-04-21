# MERCURY and Chio-Wall Product Surface Boundaries

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

The repo now has two validated product apps on Chio:

- MERCURY for governed trading-workflow evidence
- Chio-Wall for bounded information-domain control evidence

This document freezes what remains shared in Chio versus what stays product-
owned so hardening execution does not silently collapse the products together.

---

## Shared Chio Substrate

The following services stay Chio-owned and must remain generic:

- `receipt_truth` via `crates/chio-core` and `crates/chio-kernel`
- `checkpoint_publication` via `crates/chio-kernel` and `crates/chio-anchor`
- `offline_evidence_export` via `crates/chio-control-plane` and `crates/chio-kernel`
- `proof_verification` via `crates/chio-control-plane` and `crates/chio-cli`

These services are shared because both product apps depend on the same receipt,
checkpoint, export, and verification truth. Neither product is allowed to fork
those semantics locally.

---

## Product-Owned Surfaces

### MERCURY

- binary: `mercury`
- app crate: `crates/chio-mercury`
- core crate: `crates/chio-mercury-core`
- docs root: `docs/mercury`
- boundary: controlled release, rollback, and inquiry evidence for AI-assisted
  execution workflow changes

Owned surfaces:

- pilot export
- supervised-live export and qualification
- downstream review export
- governance-workbench export
- assurance-suite export
- embedded OEM export
- trust-network export

### Chio-Wall

- binary: `chio-wall`
- app crate: `crates/chio-wall`
- core crate: `crates/chio-wall-core`
- docs root: `docs/chio-wall`
- boundary: tool-boundary control evidence for one bounded `research ->
  execution` information-domain barrier workflow

Owned surfaces:

- control-path export
- control-path validate
- denied cross-domain tool-access evidence

---

## Ownership and Support

- shared Chio release owner: `chio-release-control`
- shared trust-material owner: `chio-key-custody`
- MERCURY release owner: `mercury-platform-owner`
- MERCURY support owner: `mercury-product-ops`
- Chio-Wall release owner: `barrier-control-room`
- Chio-Wall support owner: `chio-wall-ops`

The release owners control product packaging. Shared receipt and checkpoint key
custody remains outside both product apps.

---

## Canonical Commands

Export the current machine-readable boundary package:

```bash
cargo run -p chio-cli -- product-surface export --output target/chio-product-surface-hardening-export
```

Validate the boundary package and write the explicit decision artifact:

```bash
cargo run -p chio-cli -- product-surface validate --output target/chio-product-surface-hardening-validation
```

---

## Deferred Scope

This hardening lane does not authorize:

- new MERCURY workflow lanes
- additional Chio-Wall buyer motions
- a merged multi-product shell
- a generic platform console
- new companion products
