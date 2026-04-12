# Platform Hardening Decision Record

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Decision

`continue_current_product_set_hardening_only`

Continue hardening only for the current MERCURY plus ARC-Wall product set.

---

## Approved Scope

- one explicit shared ARC service catalog for MERCURY and ARC-Wall
- one shared ARC dependency map for the current product set
- one cross-product release and trust-material governance model
- one cross-product release matrix and approval boundary
- one shared trust-material recovery drill and operator alert-routing model
- one fail-closed boundary-regression suite and validation package over the
  current product set only

---

## Deferred Scope

- new MERCURY workflow lanes
- additional ARC-Wall buyer motions
- a merged platform shell
- a generic console UX
- new companion products

---

## Rationale

The repo now has one explicit shared-service boundary and one executed
hardening package for the current product set. The honest next step remains
current-product-set hardening, not a new feature lane, buyer motion, console,
or companion product. This keeps ARC generic, MERCURY opinionated, and
ARC-Wall separate.
