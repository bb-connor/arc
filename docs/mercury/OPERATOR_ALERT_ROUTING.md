# Operator Alert Routing

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

This routing model distinguishes Chio substrate incidents from MERCURY-only,
Chio-Wall-only, and trust-material incidents across the current product set.

---

## Incident Classes

### Shared substrate

- owning team: `chio-release-control`
- affected products: MERCURY, Chio-Wall
- use when Chio-owned receipt, checkpoint, export, or verifier truth is at risk

### MERCURY product

- owning team: `mercury-product-ops`
- affected products: MERCURY
- use when the incident is product-local and does not weaken shared Chio truth

### Chio-Wall product

- owning team: `chio-wall-ops`
- affected products: Chio-Wall
- use when the incident is product-local and does not weaken shared Chio truth

### Trust material

- owning team: `chio-key-custody`
- affected products: MERCURY, Chio-Wall
- use when custody, rotation, or verification state changes for shared Chio
  trust material

---

## Fail-Closed Rule

Alerts that cannot be classified as product-local default to the shared Chio
substrate route and pause both product lanes until triage completes.

---

## Canonical Command

```bash
cargo run -p chio-cli -- product-surface export --output target/chio-product-surface-hardening-export
```

The export package writes `operator-alert-routing.json`.
