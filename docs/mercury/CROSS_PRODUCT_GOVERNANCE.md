# Cross-Product Governance on ARC

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

This runbook defines the release, incident, and trust-material operating model
for the current ARC product set:

- MERCURY
- ARC-Wall

The goal is to keep the products separate while making shared ARC substrate
ownership explicit.

This milestone now executes that model through a shared dependency map, a
release matrix, a trust-material recovery drill, and operator alert routing.

---

## Release Control

Shared release approvers:

- `arc-release-control`
- `mercury-platform-owner`
- `barrier-control-room`

Release classes:

1. ARC substrate change
   Applies when receipt, checkpoint, export, or verifier truth changes.
2. MERCURY-only change
   Applies when MERCURY package families or product-local docs change without
   altering shared ARC truth.
3. ARC-Wall-only change
   Applies when the bounded control-path package or ARC-Wall docs change
   without altering shared ARC truth.

ARC substrate changes require cross-product review because both apps consume
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

- custody owner: `arc-key-custody`
- release authority: `arc-release-control`

Fail-closed rule:

If shared trust material is degraded, rotated incorrectly, or unverifiable,
both product release lanes pause until ARC substrate integrity is restored.

---

## Incident Routing

Escalation path:

1. product support owner triages first
2. `arc-release-control` coordinates cross-product release gates
3. `arc-key-custody` handles shared trust-material recovery

Routing principle:

- MERCURY incidents stay with `mercury-product-ops` unless they threaten ARC
  receipt, checkpoint, export, or verifier truth
- ARC-Wall incidents stay with `arc-wall-ops` unless they threaten those same
  shared ARC services

The canonical machine-readable operator-routing model now lives in
`operator-alert-routing.json`.

---

## Non-Goals

This governance model does not create:

- a merged product shell
- a generic platform console
- a new buyer or connector program
