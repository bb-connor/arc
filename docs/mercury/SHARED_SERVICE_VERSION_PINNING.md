# Shared Service Version Pinning

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

This runbook pins the Chio-owned shared substrate crates that both MERCURY and
Chio-Wall consume. The goal is to make shared-substrate drift explicit and
fail-closed before release control, recovery routing, or qualification claims
are made.

---

## Shared Chio Dependency Map

- dependency map id: `chio-shared-substrate.v1`
- workspace version: `0.1.0`

Pinned shared crates:

- `chio-core`
- `chio-kernel`
- `chio-anchor`
- `chio-control-plane`
- `chio-cli`

These crates remain Chio-owned and generic even when MERCURY and Chio-Wall ship
different product packages.

---

## Fail-Closed Rules

- A shared Chio crate version change is treated as a shared-substrate release.
- MERCURY-only or Chio-Wall-only packaging changes do not authorize drift in
  the shared Chio dependency map.
- If the shared dependency map cannot be reconciled across the current product
  set, both product release lanes pause.

---

## Canonical Command

```bash
cargo run -p chio-cli -- product-surface export --output target/chio-product-surface-hardening-export
```

The export package writes `shared-dependency-map.json` beside the product
surface manifests and the shared-service catalog.
