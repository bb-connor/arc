# Shared Service Version Pinning

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

This runbook pins the ARC-owned shared substrate crates that both MERCURY and
ARC-Wall consume. The goal is to make shared-substrate drift explicit and
fail-closed before release control, recovery routing, or qualification claims
are made.

---

## Shared ARC Dependency Map

- dependency map id: `arc-shared-substrate.v1`
- workspace version: `0.1.0`

Pinned shared crates:

- `arc-core`
- `arc-kernel`
- `arc-anchor`
- `arc-control-plane`
- `arc-cli`

These crates remain ARC-owned and generic even when MERCURY and ARC-Wall ship
different product packages.

---

## Fail-Closed Rules

- A shared ARC crate version change is treated as a shared-substrate release.
- MERCURY-only or ARC-Wall-only packaging changes do not authorize drift in
  the shared ARC dependency map.
- If the shared dependency map cannot be reconciled across the current product
  set, both product release lanes pause.

---

## Canonical Command

```bash
cargo run -p arc-cli -- product-surface export --output target/arc-product-surface-hardening-export
```

The export package writes `shared-dependency-map.json` beside the product
surface manifests and the shared-service catalog.
