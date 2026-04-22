# Cross-Product Governance on Chio

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

This runbook defines the release, incident, and trust-material operating model
for the current Chio product set:

- MERCURY
- Chio-Wall

The goal is to keep the products separate while making shared Chio substrate
ownership explicit.

This milestone now executes that model through a shared dependency map, a
release matrix, a trust-material recovery drill, and operator alert routing.

---

## Release Control

Shared release approvers:

- `chio-release-control`
- `mercury-platform-owner`
- `barrier-control-room`

Release classes:

1. Chio substrate change
   Applies when receipt, checkpoint, export, or verifier truth changes.
2. MERCURY-only change
   Applies when MERCURY package families or product-local docs change without
   altering shared Chio truth.
3. Chio-Wall-only change
   Applies when the bounded control-path package or Chio-Wall docs change
   without altering shared Chio truth.

Chio substrate changes require cross-product review because both apps consume
the same shared receipt and checkpoint foundations.

The canonical machine-readable release matrix now lives in
`cross-product-release-matrix.json`.

---

## Trust-Material Boundaries

Shared trust material:

- receipt-signing keys
- checkpoint-publication keys
- product-release packaging approvals

Ownership:

- custody owner: `chio-key-custody`
- release authority: `chio-release-control`

Fail-closed rule:

If shared trust material is degraded, rotated incorrectly, or unverifiable,
both product release lanes pause until Chio substrate integrity is restored.

---

## Incident Routing

Escalation path:

1. product support owner triages first
2. `chio-release-control` coordinates cross-product release gates
3. `chio-key-custody` handles shared trust-material recovery

Routing principle:

- MERCURY incidents stay with `mercury-product-ops` unless they threaten Chio
  receipt, checkpoint, export, or verifier truth
- Chio-Wall incidents stay with `chio-wall-ops` unless they threaten those same
  shared Chio services

The canonical machine-readable operator-routing model now lives in
`operator-alert-routing.json`.

---

## Non-Goals

This governance model does not create:

- a merged product shell
- a generic platform console
- a new buyer or connector program
