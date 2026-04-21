# Cross-Product Release Matrix

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

This matrix distinguishes shared Chio substrate changes from MERCURY-only and
Chio-Wall-only changes for the current product set.

---

## Release Classes

### `shared_substrate`

- affected products: MERCURY, Chio-Wall
- required approvers:
  - `chio-release-control`
  - `mercury-platform-owner`
  - `barrier-control-room`
- pause scope: both product lanes
- rollback owner: `chio-release-control`

### `mercury_only`

- affected products: MERCURY
- required approvers:
  - `mercury-platform-owner`
  - `chio-release-control`
- pause scope: MERCURY only
- rollback owner: `mercury-platform-owner`

### `chio_wall_only`

- affected products: Chio-Wall
- required approvers:
  - `barrier-control-room`
  - `chio-release-control`
- pause scope: Chio-Wall only
- rollback owner: `barrier-control-room`

---

## Control Boundary

Shared Chio changes require cross-product review because both apps consume the
same receipt, checkpoint, export, and verifier truth. Product-local changes
can remain product-scoped only when the shared dependency map is unchanged.

---

## Canonical Command

```bash
cargo run -p chio-cli -- product-surface export --output target/chio-product-surface-hardening-export
```

The export package writes `cross-product-release-matrix.json`.
