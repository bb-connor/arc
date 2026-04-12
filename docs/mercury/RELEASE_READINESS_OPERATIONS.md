# MERCURY Release Readiness Operations

**Date:** 2026-04-03  
**Milestone:** `v2.53`

---

## Purpose

The release-readiness lane delivers one bounded Mercury package to one partner
path while preserving reviewer evidence and operator controls. This runbook
defines the minimum artifact set, release checks, escalation rules, and
support handoff for that path.

---

## Required Bundle Components

Every `release-readiness export` bundle must include:

- one release-readiness profile
- one release-readiness package
- one partner-delivery manifest
- one delivery acknowledgement
- one operator release checklist
- one escalation manifest
- one support handoff
- one proof package
- one inquiry package
- one inquiry verification report
- one assurance-suite package
- one trust-network package
- one reviewer package
- one qualification report

The bundle is incomplete if any of those files are missing, inconsistent, or
cannot be matched back to the same workflow.

---

## Operating Boundary

- release owner: `mercury-release-manager`
- partner owner: `mercury-partner-delivery`
- Mercury support owner: `mercury-release-ops`

The release owner signs off on the bounded launch lane. The partner owner
acknowledges delivery. Mercury support owns fail-closed recovery whenever the
bundle contents, escalation file, or support handoff become incomplete.

---

## Fail-Closed Rules

The release-readiness path must fail closed when:

- the release-readiness profile and package disagree on audiences or delivery
  surface
- the partner-delivery manifest omits proof, inquiry, assurance, or trust-
  network files
- the reviewer package or qualification report cannot be matched to the same
  workflow
- the operator release checklist is incomplete at launch time
- the escalation manifest or support handoff is missing

Recovery posture:

1. stop the partner delivery immediately
2. regenerate the release-readiness export from the canonical trust-network
   lane
3. require a fresh acknowledgement before treating the bundle as launchable

---

## Deferred Operations

This runbook does not authorize:

- multiple partner-delivery surfaces
- a generic ARC release console
- a merged Mercury and ARC-Wall release shell
- new Mercury product-line claims
- multi-product packaging unification

Those remain separate decisions, not hidden responsibilities inside `v2.53`.
