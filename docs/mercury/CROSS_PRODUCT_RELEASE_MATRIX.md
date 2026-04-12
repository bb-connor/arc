# Cross-Product Release Matrix

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

This matrix distinguishes shared ARC substrate changes from MERCURY-only and
ARC-Wall-only changes for the current product set.

---

## Release Classes

### `shared_substrate`

- affected products: MERCURY, ARC-Wall
- required approvers:
  - `arc-release-control`
  - `mercury-platform-owner`
  - `barrier-control-room`
- pause scope: both product lanes
- rollback owner: `arc-release-control`

### `mercury_only`

- affected products: MERCURY
- required approvers:
  - `mercury-platform-owner`
  - `arc-release-control`
- pause scope: MERCURY only
- rollback owner: `mercury-platform-owner`

### `arc_wall_only`

- affected products: ARC-Wall
- required approvers:
  - `barrier-control-room`
  - `arc-release-control`
- pause scope: ARC-Wall only
- rollback owner: `barrier-control-room`

---

## Control Boundary

Shared ARC changes require cross-product review because both apps consume the
same receipt, checkpoint, export, and verifier truth. Product-local changes
can remain product-scoped only when the shared dependency map is unchanged.

---

## Canonical Command

```bash
cargo run -p arc-cli -- product-surface export --output target/arc-product-surface-hardening-export
```

The export package writes `cross-product-release-matrix.json`.
