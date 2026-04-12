# MERCURY and ARC-Wall Product Surface Boundaries

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

The repo now has two validated product apps on ARC:

- MERCURY for governed trading-workflow evidence
- ARC-Wall for bounded information-domain control evidence

This document freezes what remains shared in ARC versus what stays product-
owned so hardening execution does not silently collapse the products together.

---

## Shared ARC Substrate

The following services stay ARC-owned and must remain generic:

- `receipt_truth` via `crates/arc-core` and `crates/arc-kernel`
- `checkpoint_publication` via `crates/arc-kernel` and `crates/arc-anchor`
- `offline_evidence_export` via `crates/arc-control-plane` and `crates/arc-kernel`
- `proof_verification` via `crates/arc-control-plane` and `crates/arc-cli`

These services are shared because both product apps depend on the same receipt,
checkpoint, export, and verification truth. Neither product is allowed to fork
those semantics locally.

---

## Product-Owned Surfaces

### MERCURY

- binary: `mercury`
- app crate: `crates/arc-mercury`
- core crate: `crates/arc-mercury-core`
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

### ARC-Wall

- binary: `arc-wall`
- app crate: `crates/arc-wall`
- core crate: `crates/arc-wall-core`
- docs root: `docs/arc-wall`
- boundary: tool-boundary control evidence for one bounded `research ->
  execution` information-domain barrier workflow

Owned surfaces:

- control-path export
- control-path validate
- denied cross-domain tool-access evidence

---

## Ownership and Support

- shared ARC release owner: `arc-release-control`
- shared trust-material owner: `arc-key-custody`
- MERCURY release owner: `mercury-platform-owner`
- MERCURY support owner: `mercury-product-ops`
- ARC-Wall release owner: `barrier-control-room`
- ARC-Wall support owner: `arc-wall-ops`

The release owners control product packaging. Shared receipt and checkpoint key
custody remains outside both product apps.

---

## Canonical Commands

Export the current machine-readable boundary package:

```bash
cargo run -p arc-cli -- product-surface export --output target/arc-product-surface-hardening-export
```

Validate the boundary package and write the explicit decision artifact:

```bash
cargo run -p arc-cli -- product-surface validate --output target/arc-product-surface-hardening-validation
```

---

## Deferred Scope

This hardening lane does not authorize:

- new MERCURY workflow lanes
- additional ARC-Wall buyer motions
- a merged multi-product shell
- a generic platform console
- new companion products
