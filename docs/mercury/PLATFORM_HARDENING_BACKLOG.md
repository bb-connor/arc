# Platform Hardening Backlog

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

This backlog captures the bounded hardening work now being executed for
sustained multi-product operation across the current ARC product set without
opening another expansion lane.

---

## Active Product Set

- MERCURY
- ARC-Wall

---

## Prioritized Items

### 1. `shared-service-version-pinning`

- area: shared services
- owner hint: `arc-release-control`
- goal: pin one shared ARC dependency map across both product release lanes
- execution status: encoded in `shared-dependency-map.json`

### 2. `cross-product-release-matrix`

- area: release governance
- owner hint: `arc-release-control`
- depends on: `shared-service-version-pinning`
- goal: define who approves shared substrate changes versus product-only changes
- execution status: encoded in `cross-product-release-matrix.json`

### 3. `trust-material-recovery-drill`

- area: trust material
- owner hint: `arc-key-custody`
- depends on: `cross-product-release-matrix`
- goal: exercise one shared recovery drill for receipt and checkpoint trust
  material
- execution status: encoded in `trust-material-recovery-drill.json`

### 4. `operator-alert-routing`

- area: operator tooling
- owner hint: `mercury-product-ops`
- depends on: `cross-product-release-matrix`
- goal: distinguish ARC substrate incidents from product-local incidents in
  alert routing
- execution status: encoded in `operator-alert-routing.json`

### 5. `portfolio-boundary-regression-suite`

- area: qualification
- owner hint: `arc-platform-assurance`
- depends on:
  - `shared-service-version-pinning`
  - `cross-product-release-matrix`
  - `trust-material-recovery-drill`
- goal: fail closed if a shared service drops out of ARC ownership or if one
  product surface blurs into the other
- execution status: encoded in `boundary-regression-suite.json`

---

## Deferred Scope

This backlog does not authorize:

- new MERCURY workflow lanes
- additional ARC-Wall buyer motions
- a generic console UX
- new companion products
