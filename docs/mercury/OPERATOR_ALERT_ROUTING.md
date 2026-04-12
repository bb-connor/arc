# Operator Alert Routing

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

This routing model distinguishes ARC substrate incidents from MERCURY-only,
ARC-Wall-only, and trust-material incidents across the current product set.

---

## Incident Classes

### Shared substrate

- owning team: `arc-release-control`
- affected products: MERCURY, ARC-Wall
- use when ARC-owned receipt, checkpoint, export, or verifier truth is at risk

### MERCURY product

- owning team: `mercury-product-ops`
- affected products: MERCURY
- use when the incident is product-local and does not weaken shared ARC truth

### ARC-Wall product

- owning team: `arc-wall-ops`
- affected products: ARC-Wall
- use when the incident is product-local and does not weaken shared ARC truth

### Trust material

- owning team: `arc-key-custody`
- affected products: MERCURY, ARC-Wall
- use when custody, rotation, or verification state changes for shared ARC
  trust material

---

## Fail-Closed Rule

Alerts that cannot be classified as product-local default to the shared ARC
substrate route and pause both product lanes until triage completes.

---

## Canonical Command

```bash
cargo run -p arc-cli -- product-surface export --output target/arc-product-surface-hardening-export
```

The export package writes `operator-alert-routing.json`.
